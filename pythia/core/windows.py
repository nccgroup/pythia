import io
import logging
import struct
import pefile
from binascii import hexlify
from .helpers import LicenseHelper, PackageInfoHelper
from .structures import *

from plum import unpack_from
from plum.structure import Structure, member
from plum.int.little import UInt32

class Vftable(Structure):
    vmtSelfPtr: UInt32
    vmtIntfTable: UInt32
    vmtAutoTable: UInt32
    vmtInitTable: UInt32
    vmtTypeInfo: UInt32
    vmtFieldTable: UInt32
    vmtMethodTable: UInt32
    vmtDynamicTable: UInt32
    vmtClassName: UInt32
    vmtInstanceSize: UInt32
    vmtParent: UInt32

class PEHelper(object):
    """
    A very basic OO wrapper around pefile, making it easier to obtain data
    without repeating code.
    """

    def __init__(self, pe):
        self._pe = pe
        self.logger = logging.getLogger("pehelper")

    def get_resource_data(self, resource_type, resource_name):

        pe = self._pe
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )

        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            self.logger.warning(
                "This executable has no resources, expected DVCLAL license information"
            )
            return

        for directory in pe.DIRECTORY_ENTRY_RESOURCE.entries:

            if directory.id != resource_type:
                continue

            for entry in directory.directory.entries:
                if str(entry.name) == resource_name:
                    offset = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size
                    data = pe.get_memory_mapped_image()[offset : offset + size]
                    return data

        return None


class PEHandler(object):
    """
    The main parser, which takes a filename or pefile object and extracts
    information.  If pythia is updated to parse other file types then
    much of the code will need splitting out into a separate class.
    """

    # TODO: Support callbacks, which will allow other programs (idapython,
    #       radare) to use this programatically.  Ideally these should be
    #       passed to the higher level class.

    # TODO: Support parsing a single section, if given the data and the
    #       base virtual address.  This will permit usage from within
    #       IDA.

    # TODO: Some way of mapping from Construct Struct(..) types to the
    #       original data, so we can more easily interface with IDA/r2/etc.

    _pe = None
    profiles = {
        "delphi_legacy": {
            "description": "Delphi (legacy)",
            "distance": 0x4C,
            "vftable_struct": vftable_legacy,
        },
        "delphi_modern": {
            "description": "Delphi (modern)",
            "distance": 0x58,
            "vftable_struct": vftable_modern,
        },
    }
    chosen_profile = None
    visited = None
    candidates = None

    def __init__(self, logger, filename=None, pe=None):
        self.logger = logger
        self._reset_queues(reset_visited=True)

        if filename:
            self._from_file(filename)

        elif pe:
            self._from_pefile(pe)

    def _reset_queues(self, reset_visited=False):
        """
        Initialise (or reset) the local work queues.  By default the queue
        of visited locations is not reset, as this should only occur once at
        startup.
        """

        if reset_visited:
            self.visited = {}

        self.candidates = {}

        # Initialise empty lists
        for table in ["typeinfo", "fieldtable", "methodtable"]:
            if reset_visited:
                self.visited[table] = set()
            self.candidates[table] = set()

    def _from_pefile(self, pe):
        """
        Initialise with an existing pefile object, useful when some other
        script has already created the object.
        """
        self._pe = pe
        self._pehelper = PEHelper(pe)
        self._mapped_data = self._pe.get_memory_mapped_image()
        self.logger.debug("size of mapped data is: {}".format(len(self._mapped_data)))

        # TODO: Validate 32bit.  Need to find 64bit samples to add parsing.
        self._extract_access_license(pe)
        self._extract_packageinfo(pe)

        self.logger.debug(
            "ImageBase is: 0x{:08x}".format(self._pe.OPTIONAL_HEADER.ImageBase)
        )

    def _from_file(self, filename):
        """
        Initialise from a file on disk.
        """

        # TODO: Exception handling - test with junk data
        pe = pefile.PE(filename, fast_load=True)
        self._from_pefile(pe)
        self.logger.info("Loaded PE from file {}".format(filename))

    def _extract_access_license(self, pe):
        """
        Extract information from the DVCLAL resource.
        """

        helper = LicenseHelper()
        resource_type = pefile.RESOURCE_TYPE["RT_RCDATA"]
        data = self._pehelper.get_resource_data(resource_type, "DVCLAL")

        if data:
            license = helper.from_bytes(data)
            if license:
                self.logger.debug(
                    "Found Delphi %s license information in PE resources", license
                )
            else:
                self.logger.debug(
                    "Unknown Delphi license %s", hexlify(license)
                )

        else:
            self.logger.warning(
                "Did not find DVCLAL license information in PE resources"
            )

    def _extract_packageinfo(self, pe):
        """
        Extract information about what units this executable contains.
        """

        helper = PackageInfoHelper()
        resource_type = pefile.RESOURCE_TYPE["RT_RCDATA"]
        data = self._pehelper.get_resource_data(resource_type, "PACKAGEINFO")

        if data:
            # TODO: Get the output and do something with it
            helper.from_bytes(data)

        else:
            self.logger.warning(
                "Did not find PACKAGEINFO DVCLAL license information in PE resources"
            )


    def analyse(self):

        # TODO: Find a sample that has objects in more than one section,
        #       as this will break a number of assumptions made throughout

        sections = self._find_code_sections()
        found = False

        for s in sections:
            # Step 1 - hunt for vftables
            vftables = self._find_vftables(s)

            if vftables:
                if not found:
                    found = True
                else:
                    self.logger.warning(
                        "Have already found objects in a different section!"
                    )
                    raise Exception("Objects in more than one section")

                # Step 2 - add item references from vftables
                for offset, data in vftables.items():
                    if data["vmtFieldTable"]:
                        self._add_candidate(data["vmtFieldTable"], "fieldtable")

                    if data["vmtMethodTable"]:
                        self._add_candidate(data["vmtMethodTable"], "methodtable")

                # Step 3 - iterate through all items repeatedly
                passes = 0
                while True:
                    found = 0
                    passes += 1

                    self.logger.info(
                        "Extracting additional data, pass {}".format(passes)
                    )

                    if passes > 16:
                        self.logger.error(
                            "Too many passes, aborting.  Please report this error"
                        )
                        break

                    # Can't update items whilst iterating, so take a local copy
                    candidates = self.candidates
                    self._reset_queues()

                    for table, data in candidates.items():
                        func = getattr(self, "_parse_{}".format(table))
                        for va in sorted(data):
                            found += 1
                            self._add_visited(va, table)
                            func(s, va)

                    if found == 0:
                        break

            # self._parse_extra(s, vftables)

        if not self.chosen_profile:
            self.logger.error(
                "Didn't find any vftables.  Either this isn't Delphi, it doesn't use object orientation, or this is a bug."
            )
            return

        # TODO: Ensure the top class is always TObject, or warn
        # TODO: Check all parent classes have been found during the automated scan
        # TODO: Build up a hierachy of classes

    def _add_candidate(self, va, table):
        if va in self.visited[table]:
            return

        self.candidates[table].add(va)

    def _add_visited(self, va, table):
        self.visited[table].add(va)

    def _parse_typeinfo(self, section, va):
        self.logger.debug("found typeinfo at 0x{:08x}".format(va))

        start = va - section["base_va"]
        section["data"].seek(start)
        table = typeinfo.parse_stream(section["data"])
        self.logger.debug(table)

        # Process references to parent or linked typeinfo structures
        for ref in ["TypeinfoPtr", "ParentPtr"]:
            if hasattr(table.Data, ref):
                ptr = getattr(table.Data, ref)

                # Some parent / typeinfo pointers appear to hold data
                # that is not actually a PPTypeInfo
                if self._in_section(section, ptr):
                    typeinfo_va = self._deref_pp(section, ptr)
                    self._add_candidate(typeinfo_va, "typeinfo")

        if table.Type == types.tkDynArray:
            for ref in ["ElementTypePtr", "ElementType2Ptr", "unk5"]:
                ptr = getattr(table.Data, ref)

                if self._in_section(section, ptr):
                    typeinfo_va = self._deref_pp(section, ptr)
                    self._add_candidate(typeinfo_va, "typeinfo")
                else:
                    self.logger.debug(
                        "ptr {} to 0x{:08x} is not in this section".format(ref, ptr)
                    )

    def _deref_pp(self, section, va):
        """
        Follow a pointer and TODO
        """
        ptr_offset = self._va_to_offset(section, va)
        section["data"].seek(ptr_offset)
        (value,) = self._unpack_stream("I", section["data"])
        return value

    def _va_to_offset(self, section, va):
        return va - section["base_va"]

    def _parse_methodtable(self, section, va):

        self.logger.debug("found *method table at 0x{:08x}".format(va))

        start = self._va_to_offset(section, va)
        section["data"].seek(start)
        table = method_table.parse_stream(section["data"])

        self.logger.debug(table)

    def _parse_fieldtable(self, section, va):
        """

        """
        # TODO: This function should return a generic Fields object

        self.logger.debug(
            "found field table at 0x{:08x}".format(va))

        # TODO: Make a convenience function for va to offset
        start = va - section['base_va']
        section['data'].seek(start)
        table = field_table.parse_stream(section['data'])
        self.logger.debug(table)

        # For legacy field tables, parse the fieldtypes table and
        # extract all references to Typeinfo structures.
        if table.Legacy:
            self.logger.debug("legacy types table:")

            self.logger.debug("field types pointer: %08x", table.Legacy.FieldtypesPtr)

            # TODO: Refactor using _deref_pp
            types_offset = table.Legacy.FieldtypesPtr - section["base_va"]
            section["data"].seek(types_offset)
            types_table = fieldtypes_table.parse_stream(section["data"])

            self.logger.debug(types_table)
            for entry in types_table.Entries:
                pass

        elif table.Modern:
            # This is a pointer to a pointer, need to follow
            for field in table.Modern.Fields:

                if self._in_section(section, field.TypeinfoPtr):
                    # TODO: Refactor using _deref_pp and _va_to_offset
                    typeinfo_ptr_offset = field.TypeinfoPtr - \
                        section['base_va']
                    section['data'].seek(typeinfo_ptr_offset)
                    (typeinfo_va,) = self._unpack_stream("I", section['data'])

                    self._add_candidate(typeinfo_va, 'typeinfo')
#                    typeinfo_offset -= typeinfo_va - section['base_va']

    def _find_code_sections(self):
        """
        Iterate over all code sections in a PE file and return a dictionary
        including section data.
        """
        sections = []

        # Check each code segment to see if it has the code flag
        for section in self._pe.sections:
            if (
                section.Characteristics
                & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_CNT_CODE"]
            ):

                # pefile doesn't remove the null padding, trim any whitespace
                # TODO: Consider whether removing non-printable would be better
                name = section.Name
                # TODO: Catch decoding exceptions
                name = name.rstrip(b" \r\n\0").decode("ascii")

                raw_offset = section.PointerToRawData
                size = section.SizeOfRawData
                base = section.VirtualAddress

                base_va = self._pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                data = io.BytesIO(self._mapped_data[base : base + size])

                self.logger.debug(
                    "Found section {}, raw offset 0x{:08x}, size: 0x{:08x}, base VA: 0x{:08x}".format(
                        name, raw_offset, size, base_va
                    )
                )

                sections.append(
                    {
                        "name": name,
                        "base": base,
                        "data": data,
                        "raw_offset": section.PointerToRawData,
                        "size": size,
                        "base_va": base_va,
                    }
                )

        return sections

    # TODO: Move to util class

    def _extract_pascal_string(self, stream, offset):
        stream.seek(offset)
        (length,) = self._unpack_stream("B", stream)
        stream.seek(offset)
        (text,) = self._unpack_stream("{}p".format(length + 1), stream)
        return text

    # TODO: Move to util class

    def _in_section(self, section, va):
        """
        Validate that a virtual address exists within a section.
        """
        if not va:
            return False

        if va < section["base_va"] or va > section["base_va"] + section["size"]:
            return False

        return True

    # TODO: Move to util class
    @staticmethod
    def _unpack_stream(fmt, stream):
        """
        Unpack data from a streaming object, e.g. BytesIO().
        """
        size = struct.calcsize(fmt)
        buf = stream.read(size)
        return struct.unpack(fmt, buf)

    def _parse_extra(self, section, vftables):

        for va, v in vftables.items():

            start = v["vmtIntfTable"]
            if start:
                self.logger.debug("found intftable at 0x{:08x}".format(start))

                start -= section["base_va"]
                blah = interface_table.parse(section["mmap"][start:])

                # TODO: Refactor
                for e in blah.entries:
                    guid = e.guid
                    fields = [
                        guid.Data1,
                        guid.Data2,
                        guid.Data3,
                        guid.Data4,
                        guid.Data5,
                    ]
                    human_guid = "-".join([hexlify(d) for d in fields])
                    # self.logger.debug("*GUID: {}".format(human_guid))

                # self.logger.debug(blah)

    def _validate_vftable(self, section, offset, structure):
        """
        Validate and extract a vftable from a specific offset.
        """

        obj = unpack_from(Vftable, section["data"])
        self.logger.debug(obj)
        import plum
        dump = plum.dump(obj)

        if isinstance(obj, plum.PlumType):
            self.logger.debug("yeah it's a plum type")

        section["data"].seek(offset)
        data = structure.parse_stream(section["data"])
        # self.logger.debug(data)

        # A number of checks to ensure our brute force method has found a valid
        # vftable.  Note that legitimate code produced by the Delphi compiler
        # will often include unrelated sequences of bytes which aren't vftables
        # but pass basic checks.  Therefore this should be robust enough to
        # reject them.

        # Validate that all pointers are within the code section.  This
        # removes a lot of incorrect detections from the brute force search.
        #
        # Instance size is not a pointer, self pointer has already been
        # validated.
        ignore = ["vmtInstanceSize", "vmtSelfPtr"]

        for name, value in data.items():
            if name.startswith("vmt") and name not in ignore:
                if value and not self._in_section(section, value):
                    return None

        # Check the instantiated size is not more than 500Kib
        if data["vmtInstanceSize"] > 1024 * 500:
            self.logger.debug("Improbably large vmtInstanceSize")
            return None

        # Extract the class name
        name_offset = data["vmtClassName"] - section["base_va"]
        name = self._extract_pascal_string(section["data"], name_offset)
        # self.logger.debug("Name: {}".format(name))

        # TODO: Parse additional class functions
        # TODO: Turn into a vftable object

        return data

    def _find_vftables(self, section):
        """
        """

        matches = {}
        vftables = {}

        # TODO: This is incompatible with the user providing a default profile
        for name, profile in self.profiles.items():
            i = 0
            candidates = 0

            while i < section["size"] - profile["distance"]:
                fail = False
                section["data"].seek(i)
                (ptr,) = self._unpack_stream("I", section["data"])

                # Calculate the virtual address of this location
                va = section["base_va"] + i

                if (va + profile["distance"]) == ptr:
                    # self.logger.debug("Found a potential vftable at 0x{:08x}".format(va))

                    tmp = self._validate_vftable(section, i, profile["vftable_struct"])
                    if tmp:
                        vftables[va] = tmp
                        candidates += 1

                # TODO: 64bit incompatibility
                i += 4

            matches[name] = candidates

        # TODO: This is incompatible with the user providing a default profile
        for name, candidates in matches.items():
            if candidates > 0:
                if self.chosen_profile:
                    self.logger.error(
                        "Found more than one matching profile.  Please specify one on the commandline to continue."
                    )
                    self.logger.error(profiles)
                    sys.exit(1)
                else:
                    self.chosen_profile = self.profiles[name]

        if self.chosen_profile:
            self.logger.info(
                "Found {} vftables in section {} using profile {}".format(
                    len(vftables), section["name"], self.chosen_profile["description"]
                )
            )

        # TODO: If we don't find a profile, scan the section manually
        #       for any presence of \x07TOBJECT.

        # TODO: Consider updating a section specific vftable dict here, rather
        # than returning?
        return vftables
