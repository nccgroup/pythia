import io
import logging
from collections import OrderedDict
from struct import unpack, calcsize
from prettytable import PrettyTable
from uuid import UUID
from .utils import *

# TODO: Change naming to be more pythonic, away from Type_tkMethod etc.

class ValidationError(Exception):
    pass


class Section:

    # Where was this section in the original PE file?
    file_offset = None
    # The virtual address, from PE headers
    virtual_address = None
    # Where in memory would this section be loaded?
    load_address = None

    def __init__(self, virtual_address, size, mapped_data, stream_data, name=None):
        self.virtual_address = virtual_address
        self.size = size
        self.mapped_data = mapped_data
        self.stream_data = stream_data
        self.name = name

    def contains_va(self, va):
        """
        Check whether this section contains a given virtual address.

        For example, a section at 0x00400000 of length 0x00001000 contains 0x00410010.

        :param va: Virtual address to check
        :return: True if the VA is within the section, or False
        """
        if va >= self.load_address and va <= self.load_address + self.size:
            return True

        return False

    def offset_from_va(self, va):
        """
        Given a virtual address inside this section, calculate the offset.

        :param va: Virtual address to convert
        :return: The raw offset from start of the section corresponding to va
        """
        if not self.contains_va(va):
            raise ValueError("Virtual address %d is not within this section", va)

        return va - self.load_address

    def va_from_offset(self, offset):
        """
        Given an offset inside this section, calculate the virtual address.

        :param offset: Offset within this section to convert
        :return: The virtual address corresponsing to the offset
        """
        if offset < 0 or offset > self.size:
            raise ValueError("Offset %d is not within this section", offset)

        return offset + self.load_address

class PESection(Section):

    def __init__(self, section, mapped_data=None):
        self._section = section
        self.load_address = self._section.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

        # Map the data and keep only the relevant parts
        if mapped_data is None:
            mapped_data = self._section.pe.get_memory_mapped_image()

        stream_data = io.BytesIO(mapped_data[section.VirtualAddress : section.VirtualAddress + section.SizeOfRawData])
        mapped_data = mapped_data[section.VirtualAddress : section.VirtualAddress + section.SizeOfRawData]

        # pefile doesn't remove the null padding, trim any whitespace
        # TODO: Handle decoding exceptions
        # TODO: Validate sensible character set
        name = section.Name.rstrip(b" \r\n\0").decode("ascii")

        super().__init__(section.VirtualAddress, section.SizeOfRawData, mapped_data, stream_data, name=name)


class BaseParser:

    # TODO: Consider adding "relations", that can easily be enumerated

    def __init__(self, section, virtual_address, context, work_queue=None, parent=None):
        """

        :param stream:
        :param offset: the offset inside the stream, or None to use the current location
        :return:
        """

        self._init_logging()
        self.fields = OrderedDict()

        self.section = section
        self.stream = section.stream_data
        self.context = context

        # If provided, parsers can append to the work queue, e.g. position & type of other items
        self.work_queue = work_queue

        self.virtual_address = virtual_address
        start = section.offset_from_va(virtual_address)
        self.start = start
        self.offset = start
        self.parent = parent
        self.related = {}
        self.embedded = []

        # TODO: Consider calling a setup() class here which can be defined in concrete classes
        #       No parsers currently require this, so skipped.

        #self.logger.debug("Created a new object at VA 0x{:08x}, section offset 0x{:08x}".format(self.virtual_address, self.start))

        # Needs to be implemented by concrete classes
        self.parse()

        # TODO: Check for alignment bytes, either 0x90 or 0x8BC0 or 0x8D4000.  Not all items are
        #       fully parsed, so can't do this here.  Might be better in utility scripts for IDA
        #       or Ghidra.  This will let us spot when additional data has not been parsed.

    def _init_logging(self):
        """
        Initialise a logger with the name of this class, allowing finer control over which debug
        messages are suppressed.
        """
        name = f'{self.__module__}.{self.__class__.__qualname__}'
        self.logger = logging.getLogger(name)

    def parse_fields(self, format, names):

        # TODO: Take an optional start position - right now this assumes all reads are from the last position
        self.stream.seek(self.offset)

        # This does not allow numeric arguments, if these are required in
        # future the code will need updating.
        # TODO: Handling of C strings (zero terminated)
        valid = list("xB?HILQspGq")

        if not all(c in valid for c in format):
            raise ValueError("Invalid format string")

        if len(format) != len(names):
            raise ValueError("Format string length and number of names should match")

        i = 0

        #  This assumes single byte format specifiers (no numbers)
        for f in format:
            # TODO: For all reads, check there is enough data first
            if f == "G":
                # Special handling for GUIDs
                size = 16
                buf = self.stream.read(size)
                data = str(UUID(bytes_le = buf))

            elif f == "p":
                # Special handling for Pascal strings
                (data, raw_length) = extract_pascal_string(self.stream, self.offset)
                size = raw_length

            else:
                size = calcsize(f)

                # TODO: Error handling on .read()
                buf = self.stream.read(size)

                (data,) = unpack(f, buf)

            self.add_field(names[i], data, f, self.offset, size)
            self.offset += size
            i += 1

    def parse_bytes(self, name, num_bytes):
        """
        Manually consume into a byte array.  There is currently no format specifier for variable
        length byte data in parse_fields().  This function exists until that is fixed, or we
        decide there is no requirement for complex format strings.
        """

        data = self.stream.read(num_bytes)
        self.add_field(name, data, "B", self.offset, num_bytes)
        self.offset += num_bytes

    def embed(self, name, obj):

        # Parse the data
        va = self.section.va_from_offset(self.offset)
        embedded = obj(self.section, va, self.context, work_queue=self.work_queue, parent=self)

        # Add the object to fields
        size = len(embedded)
        self.add_field(name, embedded, None, self.offset, size)
        self.embedded.append(embedded)

        # FIXME: Move our offset ahead by the length of the new object
        self.offset += size

    def add_field(self, name, data, data_type, offset, size):
        va = self.section.va_from_offset(offset)
        data = { 'name': name, 'data': data, 'type': data_type, 'offset': offset, 'va': va, 'size': size }
        self.fields[name] = data

    def add_related(self, va, obj_type, dereference=False):
        """

        """
        # This makes it safe to call with 0, which occurs frequently, rather than each
        # caller checking for a null pointer.
        if not va:
            return

        # Many Delphi objects are pointers to pointers to objects.  Dereference these here
        # to avoid repeated code.
        if dereference:
            offset = self.section.offset_from_va(va)
            (va,) = unpack_stream("I", self.stream, offset)

        self.logger.debug("Adding a related item from object at 0x{:08x} to VA 0x{:08x} of type {}".format(self.virtual_address, va, obj_type))

        # TODO: Decide if this is still needed in future
        self.related[va] = obj_type

        if self.work_queue:
            self.work_queue.add_item(va, obj_type)

    def add_name_hint(self, name, va=None, offset=None):
        """
        Parsers can add suggested names, e.g. a virtual function table parser might name
        the location vfTObject or ptr_vfTObject so downstream parsers (e.g. IDA / Ghidra)
        can label them.
        """
        if va is None and offset is None:
            raise ValueError("Need one of va or offset")

        if offset is not None:
            va = self.section.va_from_offset(offset)

        self.context.add_name_hint(va, name)

    def get_dump(self):
        items = []

        # TODO: Add depth, so embedded objects are indented one level below in the hierarchy

        for name,data in self.fields.items():
            # Check if data is derived from BaseParser and get additional
            # dump if necessary.
            if isinstance(data["data"], BaseParser):
                items += data["data"].get_dump()
            else:
                items.append(data)

        return items

    def __str__(self):
        table = PrettyTable()
        data = self.get_dump()

        table.field_names = [ "VA", "Name", "Type", "Data", "Size"]
        for field in data:
            row = [ field["va"], field["name"], field["type"], field["data"], field["size"] ]
            table.add_row(row)

        return table.get_string()

    def __len__(self):
        """
        The length of an instance is the size (in bytes) of the fields it contains.

        :return: size of all contained fields
        """
        len = 0
        for _, data in self.fields.items():
            len += data['size']

        return len

    # TODO: dump() method
    # TODO: pack() method to repack into bytes


class UnitTable(BaseParser):
    def parse(self):
        fields = ["NumUnits", "SelfPtr"]
        self.parse_fields("II", fields)

        self.logger.debug("got number of units {}".format(self.fields["NumUnits"]["data"]))

        # Calculate the distance between what is pointed to and the location of the SelfPtr
        distance = self.fields["SelfPtr"]["data"] - self.fields["SelfPtr"]["va"]

        if distance != 4 and distance != 20:
            raise ValidationError("Error parsing unit initialisation table, got distance %d", distance)

        # Delphi 2010 onwards, process the additional embedded fields.
        if distance == 20:
            extra_fields = ["NumTypes", "TypesPtr", "NumUnitNames", "UnitNamesPtr"]
            self.parse_fields("IIII", extra_fields)

        i = 0
        while i < self.fields["NumUnits"]["data"]:
            self.embed(f"unit_{i}", UnitTableEntry)
            i += 1


class UnitTableEntry(BaseParser):
    def parse(self):
        fields = ["InitialisationPtr", "FinalisationPtr"]
        self.parse_fields("II", fields)

        # Check each field is zero OR contained within a valid section
        self._validate_ptr(self.fields["InitialisationPtr"])
        self._validate_ptr(self.fields["FinalisationPtr"])

    def _validate_ptr(self, ptr):

        # We can only validate these pointers if we have full information about the executable
        # and all of the sections it contains.
        if not self.context:
            raise ValidationError("Can't validate without context, pass context on construction")

        if ptr["data"] == 0:
            return True

        # Slightly different validation for the unit initialisation table, because Delphi >2010
        # generates multiple code sections (.text / .itext) and the pointer could be to either,
        # or a data section.
        for s in self.context.code_sections:
            if s.contains_va(ptr["data"]):
                return True

        for s in self.context.data_sections:
            if s.contains_va(ptr["data"]):
                return True

        raise ValidationError("Initialisation table pointer is not in a code section at VA %d", ptr["va"])


class Vftable(BaseParser):

    methods = OrderedDict()
    fields = OrderedDict()

    common = [
        "SelfPtr",
        "InterfaceTable",
        "AutoTable",
        "InitTable",
        "TypeInfo",
        "FieldTable",
        "MethodTable",
        "DynamicTable",
        "ClassName",
        "InstanceSize",
        "Parent",
    ]

    # TODO: Take an argument for which profile matches (legacy vs. modern Delphi)

    def parse(self):

        self.parse_fields("IIIIIIIIIII", self.common)

        # A number of checks to ensure our brute force method has found a valid
        # vftable.  Note that legitimate code produced by the Delphi compiler
        # will often include unrelated sequences of bytes which aren't vftables
        # but pass basic checks.  Therefore this should be robust enough to
        # reject them.
        self._validate_headers()

        # Extract the class name
        # TODO: Validate name
        name_offset = self.section.offset_from_va(self.fields["ClassName"]["data"])
        (self.name, _) = extract_pascal_string(self.stream, name_offset)

        # Add a relation to ClassName, which ensures the output contains
        # details about the Pascal string and where it appears in the
        # raw stream.  This is parsed later, so cannot be used now.
        self.add_related(self.fields["ClassName"]["data"], ClassName)

        # TODO: Consider adding a fake "name" object so it appears as an item in the 
        #       output and the IDA script can import it

        self.add_related(self.fields["TypeInfo"]["data"], TypeInfo)
        self.add_related(self.fields["FieldTable"]["data"], FieldTable)
        self.add_related(self.fields["MethodTable"]["data"], MethodTable)
        self.add_related(self.fields["InterfaceTable"]["data"], InterfaceTable)
        self.add_related(self.fields["InitTable"]["data"], InitialisationTable)

        self.add_name_hint(f"{self.name}VMT", offset=self.start)
        self.add_name_hint(self.name, va=self.fields["SelfPtr"]["data"])

        # TODO: Check these do not conflict (e.g. if a child class inherits from a parent, does
        #       that lead to us naming a location twice?)

        # TODO: Make this more generic, repeated code sucks
        if self.fields["AutoTable"]["data"]:
            self.add_name_hint("at{}".format(self.name), va=self.fields["AutoTable"]["data"])

        if self.fields["MethodTable"]["data"]:
            self.add_name_hint("mt{}".format(self.name), va=self.fields["MethodTable"]["data"])

        if self.fields["FieldTable"]["data"]:
            self.add_name_hint("ft{}".format(self.name), va=self.fields["FieldTable"]["data"])

        if self.fields["InitTable"]["data"]:
            self.add_name_hint("init{}".format(self.name), va=self.fields["InitTable"]["data"])

        if self.fields["InterfaceTable"]["data"]:
            self.add_name_hint("intf{}".format(self.name), va=self.fields["InterfaceTable"]["data"])

        if self.fields["DynamicTable"]["data"]:
            self.add_name_hint("dt{}".format(self.name), va=self.fields["DynamicTable"]["data"])

        if self.name.startswith("T"):
            self.logger.debug("Size of {} is {}".format(self.name, self.fields["InstanceSize"]["data"]))

        # TODO: Parse additional class functions.  Need to compare all of the table
        #       pointers, the end of the class will be just before this lowest one.

    def _validate_headers(self):
        """
        Validate that all pointers are within the code section.  This
        removes a lot of incorrect detections from the brute force search.

        Instance size is not a pointer, self pointer has already been
        validated.

        :raises: ValidationError if there are problems
        :return: True if validation is successful
        """

        ignore = ["InstanceSize", "SelfPtr"]

        for name,info in self.fields.items():
            if name in self.common and name not in ignore:
                if info['data'] and not self.section.contains_va(info['data']):
                    raise ValidationError("Field {} data points outside the code section".format(name))

        # TODO: Compare instance size from a selection of binaries and assess "normal"
        #       range of sizes.
        if self.fields["InstanceSize"]["data"] > 1024 * 500:
            raise ValidationError("Improbably large InstanceSize {}".format(self.fields["InstanceSize"]["data"]))

        return True


class ClassName(BaseParser):
    """
    This is a "fake" object to ensure class names appear in the output and
    can be imported into other tools (e.g. marking up raw data).  The class
    name is not within the vftable, so can't be directly embedded.
    """

    def parse(self):
        self.parse_fields("p", [ "name"])

        # The method of extracting an ASCII string will automatically create an exception for
        # characters outside Python's accepted range.  Consider tightening this to printable
        # ones only?


class MethodTable(BaseParser):

    def parse(self):

        self.parse_fields("H", [ "num_methods"])

        # TODO: Make an embed_many function
        i = 0
        while i < self.fields["num_methods"]["data"]:
            self.embed("method_{}".format(i), MethodEntryA)
            self.logger.debug("embedded method {}".format(i))
            self.logger.debug(self)
            i += 1

        # For Delphi 2010 onwards there is an additional WORD with a count of
        # new style method entry items.
        # TODO: Parse these
        if self.context.version.minimum >= 14:
            self.parse_fields("H", [ "num_methods_new"])
            i = 0
            while i < self.fields["num_methods_new"]["data"]:
                self.embed("method_{}".format(i), MethodEntryB)
                i += 1

class MethodEntryA(BaseParser):
    """
    Up to and including Delphi 2009
    """

    def parse(self):
        fields = ["size", "function_ptr", "name"]
        self.parse_fields("HIp", fields)

        # Consume any extra bytes
        count = 2 + 4 + self.fields["name"]["size"]
        self.parse_bytes("extra_data", self.fields["size"]["data"] - count)

class MethodEntryB(BaseParser):
    """
    Delphi 2010 onwards, this is a list of pointers to MethodEntryC objects
    with an unknown DWORD, potentially flags.
    """
    def parse(self):
        fields = ["entry_ptr", "unk1"]
        self.parse_fields("II", fields)
        self.add_related(self.fields["entry_ptr"]["data"], MethodEntryC)

class MethodEntryC(BaseParser):
    """
    """
    def parse(self):
        fields = ["size", "function_ptr", "name"]
        # Plus extra data that looks like argument types

        #  10 bytes unknown
        #  4 bytes - type pointer
        #  2 bytes - unknown (possibly argument number?)

        #  2 bytes unknown
        #  4 bytes - type pointer
        #  8 bytes unknown
        #  2 bytes unknown (possibly argument number?)
        #  name
        #  3 unknown bytes
        #  4 bytes - type pointer

        self.parse_fields("HIp", fields)
        count = 2 + 4 + self.fields["name"]["size"]
        self.parse_bytes("extra_data", self.fields["size"]["data"] - count)

        # TODO: Parse the extra data, which is name and type information for return type
        #       and arguments.

class FieldTable(BaseParser):

    def parse(self):

        self.parse_fields("H", ["header"])

        if self.fields['header']['data'] == 0:
            self._parse_type_a()

        else:
            self._parse_type_b()

        # TODO: Make field data accessible at class level

    def _parse_type_a(self):

        # The number of fields is embedded along with another (currently unknown) value
        self.parse_fields('IH', ["unk1", "num_fields"])

        i = 0
        while i < self.fields["num_fields"]["data"]:
            self.embed("field_{}".format(i), FieldEntryA)

            i += 1

    def _parse_type_b(self):
        # The object this points to is parsed as TypeTable
        self.parse_fields('I', ["typetable_ptr"])
        self.add_related(self.fields["typetable_ptr"]["data"], TypeTable)

        # The number of fields is given by the header
        i = 0
        while i < self.fields["header"]["data"]:
            self.embed("field_{}".format(i), FieldEntryB)
            i += 1

        # TODO: There is additional data following the field entries, work out what this is


class FieldEntryA(BaseParser):

    def parse(self):
        # typeinfo_ptr is a pointer to a pointer to TypeInfo
        fields = ["unk1", "typeinfo_ptr", "offset", "name", "NumExtra"]
        self.parse_fields("BIIpH", fields)

        # TODO: Validate typeinfo_ptr is within the section or raise ValidationError
        # TODO: Validate name is ASCII or raise ValidationError

        self.add_related(self.fields["typeinfo_ptr"]["data"], TypeInfo, dereference=True)

        # TODO: is this extra data valid for older versions of Delphi?

        # Read extra data, given by header minus 2 bytes
        extra = self.fields["NumExtra"]["data"] - 2
        if extra:
            # TODO: Parse this data into something more useful
            self.parse_bytes("ExtraData", extra)

            # In one case, extra bytes were:
            #   B - unknown, set to zero
            #   I - PPTypeInfo
            #   I - function pointer
            # BBB - padding?

        self.logger.debug(self)

class FieldEntryB(BaseParser):

    def parse(self):
        fields = ["offset", "type_index", "name"]
        self.parse_fields("IHp", fields)


class TypeInfo(BaseParser):

    def parse(self):
        fields = ["Type", "Name"]
        self.parse_fields("Bp", fields)

        self.add_name_hint("ti{}".format(self.fields["Name"]["data"]), offset=self.start)
        self.add_name_hint("ptr_ti{}".format(self.fields["Name"]["data"]), offset=self.start - 4)

        # TODO: Parse type specific data
        data_type = self.fields["Type"]["data"]

        # TODO: Consider a list to map these instead of if statement

        if data_type > 21:
            raise Exception("Invalid data type %d", data_type)

        # TODO: Replace these with constants which are supplied by the profile.  This will allow
        #       further support, e.g. of FreePascal.

        # tkInteger
        if data_type == 1:
            self.embed("data", Type_NumberOrChar)

        # tkChar
        elif data_type == 2:
            self.embed("data", Type_NumberOrChar)

        elif data_type == 3:
            self.embed("data", Type_Enumeration)

        elif data_type == 4:
            self.embed("data", Type_tkFloat)

        elif data_type == 6:
            self.embed("data", Type_tkSet)

        elif data_type == 7:
            self.embed("data", Type_tkClass)

        elif data_type == 8:
            self.embed("data", Type_tkMethod)

        # tkWChar
        elif data_type == 9:
            self.embed("data", Type_NumberOrChar)

        # tkLString, tkWString, tkVariant
        elif data_type == 10 or data_type == 11 or data_type == 12:
            # TODO: Do tkLString or tkWString ever have additional data?
            # TODO: Does tkVariant have additional data?
            pass

        # tkArray
        elif data_type == 13:
            self.embed("data", Type_Array)

        elif data_type == 14:
            self.embed("data", Type_tkRecord)

        elif data_type == 15:
            self.embed("data", Type_Interface)

        elif data_type == 16:
            self.embed("data", Type_Int64)

        elif data_type == 17:
            self.embed("data", Type_DynamicArray)

        # tkUstring
        elif data_type == 18:
            # No additional data observed
            pass

        elif data_type == 19:
            self.embed("data", Type_ClassReference)

        elif data_type == 20:
            self.embed("data", Type_Pointer)

        elif data_type == 21:
            self.embed("data", Type_Procedure)

        else:
            self.logger.warning("Unknown type {}".format(data_type))

class Type_Procedure(BaseParser):
    def parse(self):
        fields = [ "Flags", "CallingConvention", "unk1", "ParamCount" ]
        self.parse_fields("IIIB", fields)

        # unk1 is a PPTypeInfo, but unsure what to
        i = 0
        while i < self.fields["ParamCount"]["data"]:
            self.embed(f"param_{i}", Type_ProcedureParam)
            i += 1

class Type_ProcedureParam(BaseParser):
    def parse(self):
        fields = [ "ParamFlags", "TypeinfoPtr", "Name", "NumExtra" ]
        self.parse_fields("BIpH", fields)
        self.logger.debug(self)
        # TODO: NumExtra is a newer Delphi feature, does this happen in older binaries?




class Type_ClassReference(BaseParser):
    def parse(self):
        fields = [ "TypeinfoPtr" ]
        self.parse_fields("I", fields)
        self.add_related(self.fields["TypeinfoPtr"]["data"], TypeInfo, dereference=True)

class Type_Array(BaseParser):
    def parse(self):
        fields = [ "ArraySize", "ElementCount", "TypeinfoPtr" ]
        self.parse_fields("III", fields)
        self.add_related(self.fields["TypeinfoPtr"]["data"], TypeInfo, dereference=True)

        # TODO: Do newer Delphi versions have additional information here?


class Type_Int64(BaseParser):
    def parse(self):
        fields = [ "MinValue", "MaxValue" ]
        self.parse_fields("qq", fields)

class Type_DynamicArray(BaseParser):
    def parse(self):
        fields = ["Size", "ElementTypePtr", "VarType" ]
        self.parse_fields("III", fields)

        # TODO: Unknown DWORD (perhapas another type info pointer?) and UnitName sometimes follows these, from at least Delphi 2007

        # TODO: Add related from ElementTypePtr

class Type_tkFloat(BaseParser):

    def parse(self):
        # TODO: Float type is an enum of ftSingle (0), ftDouble, ftExtended, ftComp, ftCurr (4)
        #       which should be parsed somehow.
        fields = ["FloatType"]
        self.parse_fields("B", fields)

class Type_tkRecord(BaseParser):

    def parse(self):
        fields = ["RecordSize", "NumManagedFields"]
        self.parse_fields("II", fields)

        # Now parse managed fields

        # Now parse 1 unknown byte and get the number of records

        # Now embed records

class Type_tkSet(BaseParser):
    def parse(self):
        fields = ["unk1", "TypeinfoPtr"]
        self.parse_fields("BI", fields)

        self.add_related(self.fields["TypeinfoPtr"]["data"], TypeInfo, dereference=True)

class Type_tkMethod(BaseParser):

    def parse(self):
        fields = ["MethodType", "ParamCount"]
        self.parse_fields("BB", fields)

        i = 0
        while i < self.fields["ParamCount"]["data"]:
            self.embed(f"param_{i}", Parameter)
            i += 1

        # TODO: Check these are always present in every version of Delphi
        # These should point to a typeinfo
        i = 0

        method_types = [ 'mkProcedure', 'mkFunction', 'mkConstructor', 'mkDestructor', 'mkClassProcedure', 'mkClassFunction',
                'mkClassConstruction', 'mkOperatorOverload', 'mkSafeProcedure', 'mkSafeFunction' ]

        method_type = self.fields["MethodType"]["data"]
        if method_type > 9:
            raise ParsingException("Unknown method type %d", method_type)

        # Parse additional fields that only functions have
        if method_types[method_type] in ["mkFunction", "mkClassFunction", "mkSafeFunction" ]:
            self.parse_fields("p", [ "ReturnType" ])

            # Delphi 7 onward?  See note below
            #self.parse_fields("I", [ "ReturnTypePtr" ])
            #self.add_related(self.fields["ReturnTypePtr"]["data"], TypeInfo, dereference=True)

        # The following structures seem to be added in Delphi 7 onwards?
        # One sample from Delphi 6 does *not* have these additional fields,
        # or the ReturnTypePtr above

        # Unsure what this is, but always seems to be at least one extra
        # byte which is zero.  Does not appear to be alignment, but check.
        #self.parse_fields("B", [ "unk1" ])

        #while i < self.fields["ParamCount"]["data"]:
        #    self.logger.debug(f"this is iteration {i}")
        #    name = f"type_{i}"
        #    self.parse_fields("I", [ name ])
#
#            # TODO: Check this is within the section (or zero, which seems acceptable) as a failsafe
#            # TODO: 2c434872313f4eb54203f0ed178f727c breaks on this
#            ### DEBUG ONLY
#            self.logger.debug(self)
#            self.logger.debug("Adding a related field at 0x{:08x} from {:08x}".format(self.fields[name]["data"], self.virtual_address))
#            self.add_related(self.fields[name]["data"], TypeInfo, dereference=True)
#
#            i += 1


class Parameter(BaseParser):

    def parse(self):
        fields = ["Flags", "ParamName", "TypeName"]
        self.parse_fields("Bpp", fields)

        # TODO: Embed parameters, Type_tkMethodParam


class Type_tkClass(BaseParser):

    def parse(self):
        fields = ["class_ptr", "parent_ptr", "unk_1", "unit_name", "num_props"]
        self.parse_fields("IIHpH", fields)

        # This will be zero for base types
        self.add_related(self.fields["parent_ptr"]["data"], TypeInfo, dereference=True)

        # TODO: Parse properties
        i = 0
        while i < self.fields["num_props"]["data"]:
            self.embed("prop_{}".format(i), Property)
            i += 1


class Type_NumberOrChar(BaseParser):

    def parse(self):
        fields = ["OrdinalType", "MinValue", "MaxValue"]
        self.parse_fields("BII", fields)

        # TODO: Adjust min/max based on the ordinal type!


class Type_Enumeration(BaseParser):

    def parse(self):
        fields = ["OrdinalType", "MinValue", "MaxValue", "BaseTypePtr" ]
        self.parse_fields("BIII", fields)

        self.add_related(self.fields["BaseTypePtr"]["data"], TypeInfo, dereference=True)

        # If the BaseTypePtr points to a different enumeration then we should use the
        # labels from the parent.  If the BaseTypePtr points to itself then labels for
        # each option will be included in this object, as Pascal strings.

        # Resolve the parent of all embedded objects
        # TODO: Move this into BaseParser as a generic sub
        topmost = self
        while topmost.parent is not None:
            self.logger.debug("found a parent object: {}".format(topmost))
            topmost = topmost.parent

        self.logger.debug("topmost object is: {}".format(topmost))

        # Get VA of this object
        # TODO: Use of -4 here is a nasty fix, we should instead defererence BaseTypePtr
        #       and see if it matches.
        va = self.section.va_from_offset(topmost.start) - 4
        self.logger.debug("va is: {:08x} and basetype is {:08x}".format(va, self.fields["BaseTypePtr"]["data"]))

        if va == self.fields["BaseTypePtr"]["data"]:
            self.logger.debug("this appears to be a parent object")

            # MinValue does *not* always start at zero
            num_items = self.fields["MaxValue"]["data"] - self.fields["MinValue"]["data"]
            i = 0
            while i <= num_items:
                self.parse_fields("p", [ f"value_{i}" ])
                i += 1
        else:
            self.logger.debug("this probably inherits from parent")

        # Built-in types like Boolean don't have a UnitName, so catch the decoding error
        # as an easy way of avoiding errors.
        # TODO: Validate this approach on a large corpus.
        try:
            self.parse_fields("p", ["UnitName"])
        except UnicodeDecodeError:
            pass


class Type_Interface(BaseParser):

    def parse(self):
        fields = ["ParentPtr", "Flags", "Guid", "UnitName", "NumProperties" ]
        self.parse_fields("IBGpI", fields)

        # TODO: According to Igor S. script, Delphi >= 3 is PPTypeInfo, before is PTypeInfo

        # TODO: Enumerate properties - find a sample with tkInterface type information


class Type_Pointer(BaseParser):

    def parse(self):
        fields = ["TypePtr" ]
        self.parse_fields("I", fields)

        # TODO: Add related type TypePtr


class Property(BaseParser):

    def parse(self):
        fields = ["parent_ptr", "get_proc", "set_proc", "stored_proc", "index", "default", "name_index", "name"]
        self.parse_fields("IIIIIIHp", fields)

        self.add_related(self.fields["parent_ptr"]["data"], TypeInfo, dereference=True)

        # TODO: See page 76 of Delphi in a Nutshell for explanation of how field offsets
        #       and virtual methods are stored.


class TypeTable(BaseParser):

    def parse(self):
        fields = ["num_entries"]
        self.parse_fields("H", fields)

        # Each type is a pointer to a vftable
        i = 0
        while i < self.fields["num_entries"]["data"]:
            self.parse_fields("I", [ "type_{}".format(i) ])
            i += 1

class InterfaceTable(BaseParser):

    def parse(self):
        self.parse_fields("I", ["NumEntries"])

        i = 0
        while i < self.fields["NumEntries"]["data"]:
            self.embed(f"interface_{i}", InterfaceEntry)
            i += 1


class InterfaceEntry(BaseParser):

    def parse(self):
        fields = ["Guid", "VtablePtr", "Offset", "GetterPtr"]
        self.parse_fields("GIII", fields)

        # Each VtablePtr is a pointer to a pointer to a function.  IDA often
        # misses these (they don't have a standard prologue) and there is no
        # obvious way to identify how many 
        #
        # We should probably add a hint the location VtablePtr->Pointer->[here]
        # is code.
        #
        # Igor's script makes each entry a method (function) until the start of
        # the interface entry is reached.  This approach works, but is naive
        # because there may be multiple interface entries.


# Seems likely this is just a TypeInfo fixed to tkRecord
class InitialisationTable(BaseParser):
    def parse(self):

        # Taken from Igor's script
        fields = [ "Type", "Name", "RecordSize", "DestructibleFieldsCount" ]
        self.parse_fields("BpII", fields)

        self.logger.debug(self)

        # TODO: Add an embed_many(template, type, count) function to BaseParser
        i = 0
        while i < self.fields["DestructibleFieldsCount"]["data"]:
            self.embed(f"field_{i}", InitialisationField)
            i += 1


class InitialisationField(BaseParser):
    def parse(self):

        fields = [ "FieldTypePtr", "FieldOffset" ]
        self.parse_fields("II", fields)

        self.add_related(self.fields["FieldTypePtr"]["data"], TypeInfo, dereference=True)


