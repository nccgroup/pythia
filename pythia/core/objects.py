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
    name = None
    data = None
    size = None

    def __init__(self, virtual_address, size, data):
        self.virtual_address = virtual_address
        self.size = size
        self.data = data

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

        :param va:
        :return:
        """
        if not self.contains_va(va):
            raise ValueError("Virtual address is not within this section")

        return va - self.load_address

    def va_from_offset(self, offset):
        if offset < 0 or offset > self.size:
            raise ValueError("Offset is not within this section")

        return offset + self.load_address

class PESection(Section):

    def __init__(self, section, mapped_data=None):
        self._section = section
        self.load_address = self._section.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

        # Map the data and keep only the relevant parts
        if mapped_data is None:
            mapped_data = self._section.pe.get_memory_mapped_image()
        data = io.BytesIO(mapped_data[section.VirtualAddress : section.VirtualAddress + section.SizeOfRawData])

        # pefile doesn't remove the null padding, trim any whitespace
        # TODO: Handle decoding exceptions
        # TODO: Validate sensible character set
        self.name = section.Name.rstrip(b" \r\n\0").decode("ascii")

        super().__init__(section.VirtualAddress, section.SizeOfRawData, data)


class BaseParser:

    # TODO: Consider adding "relations", that can easily be enumerated

    def __init__(self, stream, section, start=None, parent=None):
        """

        :param stream:
        :param offset: the offset inside the stream, or None to use the current location
        :return:
        """

        # TODO: Use the full name here, or take a logger, so it's in the
        #       right heirachy
        self._init_logging()
        self.fields = OrderedDict()
        self.stream = stream
        self.section = section
        self.start = start
        self.offset = start
        self.parent = parent
        self.related = {}
        self.embedded = []

        # TODO: Consider calling a setup() class here which can be defined in concrete classes
        #       No parsers currently require this, so skipped.

        # Needs to be implemented by concrete classes
        self.parse()

        # TODO: Check for alignment bytes, either 0x90 or 0x8BC0 or 0x8D4000.  Not all items are
        #       fully parsed, so can't do this here.  Might be better in utility scripts for IDA
        #       or Ghidra.

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
        # TODO: Would this be better at class level?  Test performance
        # TODO: Handling of C strings (zero terminated)
        valid = list("xB?HILQspG")

        if not all(c in valid for c in format):
            raise ValueError("Invalid format string")

        if len(format) != len(names):
            raise ValueError("Format string length and number of names should match")

        i = 0

        #  This assumes single byte format specifiers (no numbers)
        for f in format:
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

    def embed(self, name, obj):

        # Parse the data
        embedded = obj(self.stream, self.section, self.offset, parent=self)

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

    def add_related(self, va, obj_type):
        if va:
            self.related[va] = obj_type

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
        self.add_related(self.fields["ClassName"]["data"], PascalString)

        # TODO: Consider adding a fake "name" object so it appears as an item in the 
        #       output and the IDA script can import it

        self.add_related(self.fields["TypeInfo"]["data"], TypeInfo)
        self.add_related(self.fields["FieldTable"]["data"], FieldTable)
        self.add_related(self.fields["MethodTable"]["data"], MethodTable)
        self.add_related(self.fields["InterfaceTable"]["data"], InterfaceTable)

        # TODO: Parse additional class functions

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


class PascalString(BaseParser):
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

        i = 0
        while i < self.fields["num_methods"]["data"]:
            self.embed("method_{}".format(i), MethodEntry)
            i += 1


class MethodEntry(BaseParser):

    def parse(self):
        fields = ["size", "function_ptr", "name"]
        self.parse_fields("HIp", fields)


class FieldTable(BaseParser):

    def parse(self):

        self.parse_fields("H", ["header"])

        if self.fields['header']['data'] == 0:
            self._parse_type_a()

        else:
            # FIXME: Implement parsing for legacy fields
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
        fields = ["unk1", "typeinfo_ptr", "offset", "name", "extra_bytes"]
        self.parse_fields("BIIpH", fields)

        # TODO: Validate typeinfo_ptr is within the section or raise ValidationError
        # TODO: Validate name is ASCII or raise ValidationError

        # If we've got type information, add it to related items
        if self.fields["typeinfo_ptr"]["data"]:
            # Dereference typeinfo pointer
            offset = self.section.offset_from_va(self.fields["typeinfo_ptr"]["data"])
            (ptr,) = unpack_stream("I", self.stream, offset)
            self.add_related(ptr, TypeInfo)

        # Read extra data, given by header minus 2 bytes
        if self.fields["extra_bytes"]["data"] > 2:
            # FIXME: Consume extra data
            raise NotImplementedError()


class FieldEntryB(BaseParser):

    def parse(self):
        fields = ["offset", "type_index", "name"]
        self.parse_fields("IHp", fields)


class TypeInfo(BaseParser):

    def parse(self):
        fields = ["type", "name"]
        self.parse_fields("Bp", fields)

        # TODO: Parse type specific data
        data_type = self.fields["type"]["data"]

        # TODO: Consider a list to map these instead of if statement

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

        elif data_type == 14:
            self.embed("data", Type_tkRecord)

        elif data_type == 15:
            self.embed("data", Type_Interface)

        elif data_type == 20:
            self.embed("data", Type_Pointer)

        else:
            self.logger.debug("Unknown type {}".format(data_type))

class Type_tkFloat(BaseParser):

    def parse(self):
        # TODO: Float type is an enum of ftSingle (0), ftDouble, ftExtended, ftComp, ftCurr (4)
        #       which should be parsed somehow.
        fields = ["FloatType", "NumExtra"]
        self.parse_fields("BH", fields)

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

        if self.fields["TypeinfoPtr"]["data"]:
            offset = self.section.offset_from_va(self.fields["TypeinfoPtr"]["data"])
            (typeinfo_ptr,) = unpack_stream("I", self.stream, offset)
            self.logger.error("adding type pointer to {:08x}".format(typeinfo_ptr))
            self.add_related(typeinfo_ptr, TypeInfo)

class Type_tkMethod(BaseParser):

    def parse(self):
        fields = ["MethodType", "ParamCount"]
        self.parse_fields("BB", fields)

        i = 0
        while i < self.fields["ParamCount"]["data"]:
            self.embed(f"param_{i}", Parameter)
            i += 1


class Parameter(BaseParser):

    def parse(self):
        fields = ["unk1", "ParamName", "TypeName"]
        self.parse_fields("Bpp", fields)

        # TODO: Embed parameters, Type_tkMethodParam


class Type_tkClass(BaseParser):

    def parse(self):
        fields = ["class_ptr", "parent_ptr", "unk_1", "unit_name", "num_props"]
        self.parse_fields("IIHpH", fields)

        # This will be zero for base types
        if self.fields["parent_ptr"]["data"]:
            # TODO: REVIEW AND CLEANUP.  This only finds one extra type in a 
            #       sample database, which makes no sense?  Actually this is weird,
            #       because it found an extra TypeInfo that was not found through
            #       enumerating vftables?
            self.logger.error("parent is at {:08x}".format(self.fields["parent_ptr"]["data"]))
            # TODO: Generalise this, code repeats in multiple places.  Allow
            #       add_related to take a bool flag or add a deference function?
            offset = self.section.offset_from_va(self.fields["parent_ptr"]["data"])
            (parent_ptr,) = unpack_stream("I", self.stream, offset)
            self.logger.error("adding type pointer to {:08x}".format(parent_ptr))
            self.add_related(parent_ptr, TypeInfo)

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

        # TODO: Enumeration may be followed by UnitName?

        # TODO: Add related type BaseTypePtr - in 1 test this didn't add any new objects
        if self.fields["BaseTypePtr"]["data"]:
            offset = self.section.offset_from_va(self.fields["BaseTypePtr"]["data"])
            (base_ptr,) = unpack_stream("I", self.stream, offset)
            self.logger.error("adding type pointer to {:08x}".format(base_ptr))
            self.add_related(base_ptr, TypeInfo)

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

            # MinValue always seems to be zero, but this is assumed here, perhaps incorrectly?
            i = 0
            while i <= self.fields["MaxValue"]["data"]:
                self.embed(f"value_{i}", PascalString)
                i += 1
        else:
            self.logger.debug("this probably inherits from parent")

        # Can't do this for built-in types, e.g. Boolean.  Need a nice way of ignoring
        # these whilst, perhaps by catching the exception?
        try:
            self.embed("UnitName", PascalString)
        except UnicodeDecodeError:
            pass

class Type_Interface(BaseParser):

    def parse(self):
        # TODO: unk1 is HasGuid
        # TODO: unk2 may be PropCount (according to IDA)
        fields = ["ParentPtr", "unk1", "Guid", "UnitName", "unk2" ]
        self.parse_fields("IBGpI", fields)


class Type_Pointer(BaseParser):

    def parse(self):
        fields = ["TypePtr" ]
        self.parse_fields("I", fields)

        # TODO: Add related type TypePtr


class Property(BaseParser):

    def parse(self):
        fields = ["parent_ptr", "get_proc", "set_proc", "stored_proc", "index", "default", "name_index", "name"]
        self.parse_fields("IIIIIIHp", fields)

        if self.fields["parent_ptr"]["data"]:
            offset = self.section.offset_from_va(self.fields["parent_ptr"]["data"])
            (parent_ptr,) = unpack_stream("I", self.stream, offset)
            self.logger.error("adding type pointer to {:08x}".format(parent_ptr))
            self.add_related(parent_ptr, TypeInfo)


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
