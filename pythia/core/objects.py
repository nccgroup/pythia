import io
from .parsing import BaseParser
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
        self.load_address = (
            self._section.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        )

        # Map the data and keep only the relevant parts
        if mapped_data is None:
            mapped_data = self._section.pe.get_memory_mapped_image()

        stream_data = io.BytesIO(
            mapped_data[
                section.VirtualAddress : section.VirtualAddress + section.SizeOfRawData
            ]
        )
        mapped_data = mapped_data[
            section.VirtualAddress : section.VirtualAddress + section.SizeOfRawData
        ]

        # pefile doesn't remove the null padding, trim any whitespace
        # TODO: Handle decoding exceptions
        # TODO: Validate sensible character set
        name = section.Name.rstrip(b" \r\n\0").decode("ascii")

        super().__init__(
            section.VirtualAddress,
            section.SizeOfRawData,
            mapped_data,
            stream_data,
            name=name,
        )


class ExecutableParser(BaseParser):
    """
    A customised parser, designed for use with data contained in executable files.  This class
    is modelled on Windows PE files, and assumes that data is contained within a section with
    an associated virtual address.

    This parser makes it easier to process data when there is a difference between the file offset
    (in the raw stream) and the virtual address (in the memory mapped data).
    """

    # TODO: Refactor so that section is inside context, and virtual_address is not needed (or optional)
    # def __init__(self, stream, context, start_address, work_queue=None, parent=None):
    def __init__(
        self, stream, start_address, context=None, work_queue=None, parent=None
    ):


        self.virtual_address = context.object_section.va_from_offset(start_address)
        super().__init__(stream, start_address, context, work_queue, parent)

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
            offset = self.context.object_section.offset_from_va(va)
            (va,) = unpack_stream("I", self.stream, offset)

        self.logger.debug(
            "Adding a related item from object at 0x{:08x} to VA 0x{:08x} of type {}".format(
                self.virtual_address, va, obj_type
            )
        )

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
            va = self.context.object_section.va_from_offset(offset)

        self.context.add_name_hint(va, name)

    def __str__(self):
        return super().__str__(offset=self.context.object_section.load_address)


class UnitTable(ExecutableParser):
    def parse(self):
        fields = ["NumUnits", "SelfPtr"]
        self.parse_fields("II", fields)

        self.logger.debug(
            "Number of units {}".format(self.fields["NumUnits"]["data"])
        )

        # Calculate the distance between what is pointed to and the location of the SelfPtr
        distance = self.fields["SelfPtr"][
            "data"
        ] - self.context.object_section.va_from_offset(self.fields["SelfPtr"]["offset"])

        if distance != 4 and distance != 20:
            raise ValidationError(
                "Error parsing unit initialisation table, got distance %d", distance
            )

        # Delphi 2010 onwards, process the additional embedded fields.
        if distance == 20:
            extra_fields = ["NumTypes", "TypesPtr", "NumUnitNames", "UnitNamesPtr"]
            self.parse_fields("IIII", extra_fields)

        self.embed_many("Unit", UnitTableEntry, self.fields["NumUnits"]["data"])


class UnitTableEntry(ExecutableParser):
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
            raise ValidationError(
                "Can't validate without context, pass context on construction"
            )

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

        raise ValidationError(
            "Initialisation table pointer is not in a code section at VA %d", ptr["va"]
        )


class Vftable(ExecutableParser):

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

    def _setup(self):
        self.name = None
        self.parent = None
        self.children = []
        self.methods = []

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
        name_offset = self.context.object_section.offset_from_va(self.fields["ClassName"]["data"])
        (self.name, _) = extract_pascal_string(self.stream, name_offset)

        # Add a relation to ClassName, which ensures the output contains
        # details about the Pascal string and where it appears in the
        # raw stream.  This is parsed later, so cannot be used now.
        #
        # This exists to tidy up the output (e.g. by forcing a Delphi string).
        self.add_related(self.fields["ClassName"]["data"], ClassName)

        # TODO: Consider adding a fake "name" object so it appears as an item in the
        #       output and the IDA script can import it

        self.add_related(self.fields["TypeInfo"]["data"], TypeInfo)
        self.add_related(self.fields["FieldTable"]["data"], FieldTable)
        self.add_related(self.fields["MethodTable"]["data"], MethodTable)
        self.add_related(self.fields["InterfaceTable"]["data"], InterfaceTable)
        self.add_related(self.fields["DynamicTable"]["data"], DynamicTable)
        self.add_related(self.fields["InitTable"]["data"], InitialisationTable)

        self.add_name_hint(f"{self.name}VMT", offset=self.start)
        self.add_name_hint(self.name, va=self.fields["SelfPtr"]["data"])

        # TODO: Check these do not conflict (e.g. if a child class inherits from a parent, does
        #       that lead to us naming a location twice?)

        # TODO: Make this more generic, repeated code sucks
        if self.fields["AutoTable"]["data"]:
            self.add_name_hint(
                "at{}".format(self.name), va=self.fields["AutoTable"]["data"]
            )

        if self.fields["MethodTable"]["data"]:
            self.add_name_hint(
                "mt{}".format(self.name), va=self.fields["MethodTable"]["data"]
            )

        if self.fields["FieldTable"]["data"]:
            self.add_name_hint(
                "ft{}".format(self.name), va=self.fields["FieldTable"]["data"]
            )

        if self.fields["InitTable"]["data"]:
            self.add_name_hint(
                "init{}".format(self.name), va=self.fields["InitTable"]["data"]
            )

        if self.fields["InterfaceTable"]["data"]:
            self.add_name_hint(
                "intf{}".format(self.name), va=self.fields["InterfaceTable"]["data"]
            )

        if self.fields["DynamicTable"]["data"]:
            self.add_name_hint(
                "dt{}".format(self.name), va=self.fields["DynamicTable"]["data"]
            )

        # TODO: Remove this debug code :)
        if self.name.startswith("T"):
            self.logger.debug(
                "Size of {} is {}".format(
                    self.name, self.fields["InstanceSize"]["data"]
                )
            )

        self._extract_methods()

    def _extract_methods(self):

        # Calculate the number of functions this object has.  Delphi does not store this as
        # a count, so instead we find the lowest pointer amongst the vftable properties to
        # find the "end" of the function list.
        #
        # Appears that InterfaceTable may be placed before the vftable (leading calculated
        # number of functions to be negative).
        fields = [
            "AutoTable",
            "InitTable",
            "TypeInfo",
            "FieldTable",
            "MethodTable",
            "DynamicTable",
            "ClassName",
        ]
        lowest = 0xFFFFFFFFFFFFFFFF
        for field in fields:
            try:
                address = self.fields[field]["data"]
                if address and address < lowest:
                    lowest = address
            except KeyError:
                pass

        num_methods = (self.context.object_section.offset_from_va(lowest) - self.offset) / 4
        if not num_methods.is_integer():
            self.logger.error(
                "Could not calculate the number of methods correctly, skipping"
            )
        else:
            self.logger.debug(
                "Lowest offset is {:08x}, should be {} methods".format(
                    lowest, num_methods
                )
            )

        i = 0
        while i < num_methods:
            i += 1
            field_name = "method_ptr_{}".format(i)
            self.parse_fields("I", [field_name])

            name = "{}.method{}".format(self.name, i)
            method_info = {"name": name, "va": self.fields[field_name]["data"]}
            self.methods.append(method_info)

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

        for name, info in self.fields.items():
            if name in self.common and name not in ignore:
                if info["data"] and not self.context.object_section.contains_va(info["data"]):
                    raise ValidationError(
                        "Field {} data points outside the code section".format(name)
                    )

        # TODO: Compare instance size from a selection of binaries and assess "normal"
        #       range of sizes.
        if self.fields["InstanceSize"]["data"] > 1024 * 500:
            raise ValidationError(
                "Improbably large InstanceSize {}".format(
                    self.fields["InstanceSize"]["data"]
                )
            )

        return True


class ClassName(ExecutableParser):
    """
    This is a "fake" object to ensure class names appear in the output and
    can be imported into other tools (e.g. marking up raw data).  The class
    name is not within the vftable, so can't be directly embedded.
    """

    def parse(self):
        self.parse_fields("p", ["name"])

        # The method of extracting an ASCII string will automatically create an exception for
        # characters outside Python's accepted range.  Consider tightening this to printable
        # ones only?


class MethodTable(ExecutableParser):
    def parse(self):

        self.parse_fields("H", ["num_methods"])
        self.embed_many("Method", MethodEntryA, self.fields["num_methods"]["data"])

        # For Delphi 2010 onwards there is an additional WORD with a count of
        # new style method entry items.
        # TODO: Parse these
        if self.context.version.minimum >= 14:
            self.parse_fields("H", ["num_methods_new"])
            self.embed_many(
                "Method", MethodEntryB, self.fields["num_methods_new"]["data"]
            )


class MethodEntryA(ExecutableParser):
    """
    Up to and including Delphi 2009
    """

    def parse(self):
        fields = ["size", "function_ptr", "name"]
        self.parse_fields("HIp", fields)

        # Consume any extra bytes
        count = 2 + 4 + self.fields["name"]["size"]
        self.parse_bytes("extra_data", self.fields["size"]["data"] - count)


class MethodEntryB(ExecutableParser):
    """
    Delphi 2010 onwards, this is a list of pointers to MethodEntryC objects
    with an unknown DWORD, potentially flags.
    """

    def parse(self):
        fields = ["entry_ptr", "unk1"]
        self.parse_fields("II", fields)
        self.add_related(self.fields["entry_ptr"]["data"], MethodEntryC)


class MethodEntryC(ExecutableParser):
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


class FieldTable(ExecutableParser):
    def parse(self):

        self.parse_fields("H", ["header"])

        if self.fields["header"]["data"] == 0:
            self._parse_type_a()

        else:
            self._parse_type_b()

        # TODO: Make field data accessible at class level

    def _parse_type_a(self):

        # The number of fields is embedded along with another (currently unknown) value
        self.parse_fields("IH", ["unk1", "num_fields"])
        self.embed_many("Field", FieldEntryA, self.fields["num_fields"]["data"])

    def _parse_type_b(self):
        # The object this points to is parsed as TypeTable
        self.parse_fields("I", ["typetable_ptr"])
        self.add_related(self.fields["typetable_ptr"]["data"], TypeTable)

        # The number of fields is given by the header
        self.embed_many("Field", FieldEntryB, self.fields["header"]["data"])

        # TODO: There is additional data following the field entries, work out what this is


class FieldEntryA(ExecutableParser):
    def parse(self):
        # typeinfo_ptr is a pointer to a pointer to TypeInfo
        fields = ["unk1", "typeinfo_ptr", "offset", "name", "NumExtra"]
        self.parse_fields("BIIpH", fields)

        # TODO: Validate typeinfo_ptr is within the section or raise ValidationError
        # TODO: Validate name is ASCII or raise ValidationError

        self.add_related(
            self.fields["typeinfo_ptr"]["data"], TypeInfo, dereference=True
        )

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


class FieldEntryB(ExecutableParser):
    def parse(self):
        fields = ["offset", "type_index", "name"]
        self.parse_fields("IHp", fields)


class TypeInfo(ExecutableParser):
    def parse(self):
        fields = ["Type", "Name"]
        self.parse_fields("Bp", fields)

        self.add_name_hint(
            "ti{}".format(self.fields["Name"]["data"]), offset=self.start
        )
        self.add_name_hint(
            "ptr_ti{}".format(self.fields["Name"]["data"]), offset=self.start - 4
        )

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


class Type_Procedure(ExecutableParser):
    def parse(self):
        fields = ["Flags", "CallingConvention", "unk1", "ParamCount"]
        self.parse_fields("IIIB", fields)

        # unk1 is a PPTypeInfo, but unsure what to
        self.embed_many(
            "Parameter", Type_ProcedureParam, self.fields["ParamCount"]["data"]
        )


class Type_ProcedureParam(ExecutableParser):
    def parse(self):
        fields = ["ParamFlags", "TypeinfoPtr", "Name", "NumExtra"]
        self.parse_fields("BIpH", fields)
        self.logger.debug(self)
        # TODO: NumExtra is a newer Delphi feature, does this happen in older binaries?


class Type_ClassReference(ExecutableParser):
    def parse(self):
        fields = ["TypeinfoPtr"]
        self.parse_fields("I", fields)
        self.add_related(self.fields["TypeinfoPtr"]["data"], TypeInfo, dereference=True)


class Type_Array(ExecutableParser):
    def parse(self):
        fields = ["ArraySize", "ElementCount", "TypeinfoPtr"]
        self.parse_fields("III", fields)
        self.add_related(self.fields["TypeinfoPtr"]["data"], TypeInfo, dereference=True)

        # TODO: Do newer Delphi versions have additional information here?


class Type_Int64(ExecutableParser):
    def parse(self):
        fields = ["MinValue", "MaxValue"]
        self.parse_fields("qq", fields)


class Type_DynamicArray(ExecutableParser):
    def parse(self):
        fields = ["Size", "ElementTypePtr", "VarType"]
        self.parse_fields("III", fields)

        # TODO: Unknown DWORD (perhapas another type info pointer?) and UnitName sometimes follows these, from at least Delphi 2007

        self.add_related(
            self.fields["ElementTypePtr"]["data"], TypeInfo, dereference=True
        )


class Type_tkFloat(ExecutableParser):
    def parse(self):
        # TODO: Float type is an enum of ftSingle (0), ftDouble, ftExtended, ftComp, ftCurr (4)
        #       which should be parsed somehow.
        fields = ["FloatType"]
        self.parse_fields("B", fields)


class Record(ExecutableParser):
    def parse(self):
        fields = ["TypeinfoPtr", "Offset"]
        self.parse_fields("II", fields)
        self.add_related(self.fields["TypeinfoPtr"]["data"], TypeInfo, dereference=True)


class Type_tkRecord(ExecutableParser):
    def parse(self):
        fields = ["RecordSize", "NumRecords"]
        self.parse_fields("II", fields)
        self.embed_many("Record", Record, self.fields["NumRecords"]["data"])


class Type_tkSet(ExecutableParser):
    def parse(self):
        fields = ["unk1", "TypeinfoPtr"]
        self.parse_fields("BI", fields)

        self.add_related(self.fields["TypeinfoPtr"]["data"], TypeInfo, dereference=True)


class Type_tkMethod(ExecutableParser):
    def parse(self):
        fields = ["MethodType", "ParamCount"]
        self.parse_fields("BB", fields)

        self.embed_many("Param", Parameter, self.fields["ParamCount"]["data"])

        # TODO: Check these are always present in every version of Delphi
        # These should point to a typeinfo
        i = 0

        method_types = [
            "mkProcedure",
            "mkFunction",
            "mkConstructor",
            "mkDestructor",
            "mkClassProcedure",
            "mkClassFunction",
            "mkClassConstruction",
            "mkOperatorOverload",
            "mkSafeProcedure",
            "mkSafeFunction",
        ]

        method_type = self.fields["MethodType"]["data"]
        if method_type > 9:
            raise ValidationError("Unknown method type %d", method_type)

        # Parse additional fields that only functions have
        if method_types[method_type] in [
            "mkFunction",
            "mkClassFunction",
            "mkSafeFunction",
        ]:
            self.parse_fields("p", ["ReturnType"])

            # Delphi 7 onward includes a pointer to the type (in addition to the
            # string name).
            if self.context.version.minimum >= 7:
                self.parse_fields("I", ["ReturnTypePtr"])
                self.add_related(
                    self.fields["ReturnTypePtr"]["data"], TypeInfo, dereference=True
                )

        # Delphi 7 and above also embed pointers to each of the parameter types.
        if self.context.version.minimum >= 7:

            # Unsure what this is, but always seems to be one byte before the
            # typeinfo pointers.  Always set to zero.
            self.parse_fields("B", ["unk1"])
            if self.fields["unk1"]["data"] != 0:
                raise ValidationError(
                    "Expected unknown field to be zero, investigate further"
                )

            i = 0
            while i < self.fields["ParamCount"]["data"]:
                name = f"type_{i}"
                self.parse_fields("I", [name])
                self.add_related(self.fields[name]["data"], TypeInfo, dereference=True)
                i += 1


class Parameter(ExecutableParser):
    def parse(self):
        fields = ["Flags", "ParamName", "TypeName"]
        self.parse_fields("Bpp", fields)

        # TODO: Embed parameters, Type_tkMethodParam


class Type_tkClass(ExecutableParser):
    def parse(self):
        fields = ["class_ptr", "parent_ptr", "unk_1", "unit_name", "num_props"]
        self.parse_fields("IIHpH", fields)

        # This will be zero for base types
        self.add_related(self.fields["parent_ptr"]["data"], TypeInfo, dereference=True)

        # TODO: Parse properties
        i = 0
        unit_name = self.fields["unit_name"]["data"]
        while i < self.fields["num_props"]["data"]:
            prop = self.embed("Property[{}]".format(i), Property)

            # Add name hints for Get/Set/Stored functions.  Note these can overlap,
            # so there may be multiple
            name = "{}.{}".format(unit_name, prop.fields["name"]["data"])
            if self.context.object_section.contains_va(prop.fields["get_proc"]["data"]):
                self.add_name_hint(
                    "{}_GetProc".format(name), va=prop.fields["get_proc"]["data"]
                )

            if self.context.object_section.contains_va(prop.fields["set_proc"]["data"]):
                self.add_name_hint(
                    "{}_SetProc".format(name), va=prop.fields["set_proc"]["data"]
                )

            if self.context.object_section.contains_va(prop.fields["stored_proc"]["data"]):
                self.add_name_hint(
                    "{}_StoredProc".format(name), va=prop.fields["stored_proc"]["data"]
                )

            i += 1


class Type_NumberOrChar(ExecutableParser):
    def parse(self):
        fields = ["OrdinalType", "MinValue", "MaxValue"]
        self.parse_fields("BII", fields)

        # TODO: Adjust min/max based on the ordinal type!


class Type_Enumeration(ExecutableParser):
    def parse(self):
        fields = ["OrdinalType", "MinValue", "MaxValue", "BaseTypePtr"]
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
        va = self.context.object_section.va_from_offset(topmost.start) - 4
        self.logger.debug(
            "va is: {:08x} and basetype is {:08x}".format(
                va, self.fields["BaseTypePtr"]["data"]
            )
        )

        if va == self.fields["BaseTypePtr"]["data"]:
            self.logger.debug("this appears to be a parent object")

            # MinValue does *not* always start at zero
            num_items = (
                self.fields["MaxValue"]["data"] - self.fields["MinValue"]["data"]
            )
            i = 0
            while i <= num_items:
                self.parse_fields("p", [f"value_{i}"])
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


class Type_Interface(ExecutableParser):
    def parse(self):
        fields = ["ParentPtr", "Flags", "Guid", "UnitName", "NumProperties"]
        self.parse_fields("IBGpI", fields)

        # TODO: According to Igor S. script, Delphi >= 3 is PPTypeInfo, before is PTypeInfo

        # TODO: Enumerate properties - find a sample with tkInterface type information


class Type_Pointer(ExecutableParser):
    def parse(self):
        fields = ["TypePtr"]
        self.parse_fields("I", fields)

        # TODO: Add related type TypePtr


class Property(ExecutableParser):
    def parse(self):
        fields = [
            "parent_ptr",
            "get_proc",
            "set_proc",
            "stored_proc",
            "index",
            "default",
            "name_index",
            "name",
        ]
        self.parse_fields("IIIIIIHp", fields)

        self.add_related(self.fields["parent_ptr"]["data"], TypeInfo, dereference=True)

        # TODO: See page 76 of Delphi in a Nutshell for explanation of how field offsets
        #       and virtual methods are stored.


class DynamicTable(ExecutableParser):
    def parse(self):
        fields = ["num_entries"]
        self.parse_fields("H", fields)

        # See: http://hallvards.blogspot.com/2006/04/hack-9-dynamic-method-table-structure.html

        i = 0
        while i < self.fields["num_entries"]["data"]:
            self.parse_fields("H", ["Index[{}]".format(i)])
            i += 1

        # TODO: Add parse_many function to base parser
        # These should all be pointers to functions
        i = 0
        while i < self.fields["num_entries"]["data"]:
            self.parse_fields("I", ["Method[{}]".format(i)])
            i += 1


class TypeTable(ExecutableParser):
    def parse(self):
        fields = ["num_entries"]
        self.parse_fields("H", fields)

        # Each type is a pointer to a vftable
        i = 0
        while i < self.fields["num_entries"]["data"]:
            self.parse_fields("I", ["type_{}".format(i)])
            i += 1


class InterfaceTable(ExecutableParser):
    def parse(self):
        self.parse_fields("I", ["NumEntries"])
        self.embed_many("Interface", InterfaceEntry, self.fields["NumEntries"]["data"])


class InterfaceEntry(ExecutableParser):
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
class InitialisationTable(ExecutableParser):
    def parse(self):

        # Taken from Igor's script
        fields = ["Type", "Name", "RecordSize", "DestructibleFieldsCount"]
        self.parse_fields("BpII", fields)

        # TODO: Add an embed_many(template, type, count) function to BaseParser
        self.embed_many(
            "Field", InitialisationField, self.fields["DestructibleFieldsCount"]["data"]
        )


class InitialisationField(ExecutableParser):
    def parse(self):

        fields = ["FieldTypePtr", "FieldOffset"]
        self.parse_fields("II", fields)

        self.add_related(
            self.fields["FieldTypePtr"]["data"], TypeInfo, dereference=True
        )


class RequiredUnit(BaseParser):
    def parse(self):
        fields = ["HashCode", "Name"]
        self.parse_fields("Bs")


class ContainedUnit(BaseParser):
    def parse(self):
        fields = ["Flags", "HashCode", "Name"]
        self.parse_fields("BBs")


class PackageInfo(BaseParser):
    def parse(self):
        fields = ["Flags", "RequiresCount"]
        self.parse_fields("II", fields)
        self.embed_many(
            "RequiredUnit", RequiredUnit, self.fields["RequiresCount"]["data"]
        )

        self.parse_fields("I", ["ContainsCount"])
        self.embed_many(
            "ContainedUnit", ContainedUnit, self.fields["ContainsCount"]["data"]
        )
