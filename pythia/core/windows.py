import io
import logging
import struct
import pefile
from binascii import hexlify
from .helpers import LicenseHelper, PackageInfoHelper
from .structures import *
from .objects import *
from .utils import unpack_stream


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

    _pe = None
    profiles = {
        "delphi_legacy": {
            "description": "Delphi (legacy)",
            "distance": 0x4C,
            #"vftable_struct": vftable_legacy,
        },
        "delphi_modern": {
            "description": "Delphi (modern)",
            "distance": 0x58,
            #"vftable_struct": vftable_modern,
        },
    }
    chosen_profile = None
    visited = None  # TODO: Is this required?
    candidates = None  # TODO: Is this required?
    results = None

    def __init__(self, logger, results, filename=None, pe=None):
        self.logger = logger
        self.results = results
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
            self.visited = set()

        self.candidates = {}
        self.found = []

        # Initialise empty lists
        #for table in ["typeinfo", "fieldtable", "methodtable"]:
        #    if reset_visited:
        #        self.visited[table] = set()
        #    self.candidates[table] = set()

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
                self.results.license = license
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
            self.results.units = helper

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
            self.logger.info("Analysing section {}".format(s.name))

            # Step 1 - hunt for vftables
            vftables = self._find_vftables(s)

            if vftables:
                if not found:
                    found = True
                else:
                    self.logger.warning(
                        "Have already found objects in a different section!"
                    )
                    # FIXME: Find an example file to trigger this & test improvements.
                    #        Github issue #3.
                    raise Exception("Objects in more than one section")

                # Step 2 - add initial item references from vftables
                self.results.items += self._process_related(vftables.values(), s)

            self.logger.info("Finished analysing section {}".format(s.name))

        if not self.chosen_profile:
            self.logger.error(
                "Didn't find vftables.  Either this isn't Delphi, it doesn't use object orientation, or this is a bug."
            )
            return

        # TODO: Ensure the top class is always TObject, or warn
        # TODO: In strict mode, ensure no found items overlap (offset + length)
        # TODO: Check all parent classes have been found during the automated scan
        # TODO: Build up a hierarchy of classes

    def _process_related(self, objects, section, depth=1):
        # TODO: Refactor this mess of recursion

        new_objects = []

        self.logger.info(
            "Extracting additional data, pass {}".format(depth)
        )

        depth += 1
        if depth > 16:
            return new_objects

        for o in objects:
            if o.embedded:
                new_objects += self._process_related(o.embedded, section, depth)

            for va, parser in o.related.items():
                # Don't process the same item twice
                if va in self.visited:
                    continue

                offset = section.offset_from_va(va)
                self.logger.debug("Adding type {} at VA 0x{:08x} (offset {})".format(parser, va, offset))
                new = parser(section.data, section, offset)
                self.logger.debug(new)
                new_objects.append(new)
                self.visited.add(va)

        if new_objects:
            new_objects += self._process_related(new_objects, section, depth)

        return new_objects

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
                sections.append(PESection(section, self._mapped_data))

        return sections

    def _validate_vftable(self, section, offset):
        """
        Validate and extract a vftable from a specific offset.
        """

        section.data.seek(offset)

        try:
            obj = Vftable(section.data, section, offset)
        except ValidationError:
            # TODO: Log the message at high verbosity levels
            return None

        self.results.items.append(obj)
        return obj

    def _find_vftables(self, section):
        """
        """

        matches = {}
        vftables = {}

        # TODO: This is incompatible with the user providing a default profile
        for name, profile in self.profiles.items():
            i = 0
            candidates = 0

            while i < section.size - profile["distance"]:
                fail = False
                section.data.seek(i)
                (ptr, ) = unpack_stream("I", section.data)

                # Calculate the virtual address of this location
                va = section.load_address + i

                if (va + profile["distance"]) == ptr:
                    self.logger.debug("Found a potential vftable at 0x{:08x}".format(va))

                    # TODO: Pass information about current profile
                    tmp = self._validate_vftable(section, i)
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
                    # TODO: Print a list of profiles and their description
                    sys.exit(1)
                else:
                    self.chosen_profile = self.profiles[name]

        if self.chosen_profile:
            self.logger.info(
                "Found {} vftables in section {} using profile {}".format(
                    len(vftables), section.name, self.chosen_profile["description"]
                )
            )

        # TODO: If we don't find a profile, scan the section manually
        #       for any presence of \x07TOBJECT.  Github issue #4.

        # TODO: Consider updating a section specific vftable dict here, rather
        # than returning?
        return vftables
