"""
Various helpers to provide utility functions which can also be used from other code.
"""
import logging
import pefile
import re
from binascii import unhexlify
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_REG, X86_OP_IMM
from .structures import packageinfo
from .objects import UnitTable, PackageInfo
from .utils import unpack_stream


class Helper(object):
    def __init__(self):
        self._init_logging()

    def _init_logging(self):
        """
        Initialise a logger with the name of this class, allowing finer control over which debug
        messages are suppressed.
        """
        name = f"{self.__module__}.{self.__class__.__qualname__}"
        self.logger = logging.getLogger(name)


class LicenseHelper(Helper):
    """
    Utility class to convert raw DVCLAL data to Delphi version information.
    """

    # TODO: Support "fake" Delphi licenses, where the author has calculated
    #       custom values.  Find some test samples to use.  See:
    #       https://stackoverflow.com/questions/18720045/what-are-the-list-of-all-possible-values-for-dvclal

    known_licenses = {
        "Standard": unhexlify("23785D23B6A5F31943F3400226D111C7"),
        "Professional": unhexlify("A28CDF987B3C3A7926713F090F2A2517"),
        "Enterprise": unhexlify("263D4F38C28237B8F3244203179B3A83"),
    }

    def from_bytes(self, data):
        """
        Convert a stream of bytes to a license version (Standard, Professional
        or Enterprise) or None if the license is not recognised.
        """

        for version, raw in self.known_licenses.items():
            if raw == data:
                return version

        return None


class PackageInfoHelper(Helper):
    """
    Utility class to parse PACKAGEINFO data to a list of required & contained
    units.
    """

    def __init__(self):
        # TODO: Move to a static function that can be called from anywhere
        self.logger = logging.getLogger("pythia.{}".format(self.__class__.__name__))


    # TODO: This should return a collection of objects, e.g. PackageInfo for both
    #       required and contained units.
    def from_bytes(self, data):
        """
        Convert a stream of bytes to a dictionary representation of the
        structure.
        """

        # Docs for TPackageInfoHeader at:
        # https://github.com/Fr0sT-Brutal/Delphi_MiniRTL/blob/master/SysUtils.pas#L20087
        # TODO: Replace this with a parser module
        info = packageinfo.parse(data)
        self.logger.debug(info)


class PEHelper(Helper):
    """
    A very basic OO wrapper around pefile, making it easier to obtain data
    without repeating code.
    """

    def __init__(self, pe):
        super().__init__()
        self._pe = pe

    def get_entrypoint_bytes(self, num_bytes=32):
        """
        Get a number of bytes from the entrypoint, useful for identifying toolchains.
        """
        ep = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_rva = ep + self._pe.OPTIONAL_HEADER.ImageBase
        data = self._pe.get_memory_mapped_image()[ep : ep + num_bytes]
        return data

    def get_resource_data(self, resource_type, resource_name):

        pe = self._pe
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )

        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            # TODO: This warning is not generic since the code was merged into a helper class
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


class UnitInitHelper(Helper):
    """
    Utility class to find the unit initialisation table.  This table exists within a code
    section inside the executable.  It helps to determine the extent of each unit (though
    is not perfect) and also assists with Delphi version identification.

    Layout of the unit initialisation table is:

    Delphi <2010:
       - NumUnits
       - Pointer to units table (normally immediately follows?)

    Delphi >=2010:
       - NumUnits
       - Pointer to units table
       - NumTypes (? from IDR)
       - Pointer to types table (? from IDR)
       - NumUnits1 - number of strings in table below
       - Units1    - pointer to table of strings with unit names.  IDR does nothing
                     with this, so unsure what it is?

    This gives the *initialisation order* of modules.  Last unit ends just before
    the initialisation table.  First unit is always System?  This doesn't appear
    in the initialisation table though?
    """

    def __init__(self, pehelper):
        super().__init__()

        # FIXME: Assumes Windows, Github issue #5
        self.pe = pehelper

    def find_init_table(self):

        # Look for a sequence of code like below at the entrypoint:
        #
        # CODE:0057655F B8 C8 5F 57 00    mov     eax, offset dword_575FC8
        # CODE:00576564 E8 53 08 E9 FF    call    sub_406DBC  ; SysInit
        #
        # The pointer moved into EAX is the unit initialisation table.  The
        # contents of the 'start' function vary a lot depending on compiler,
        # but the call to SysInit is predictable.

        data = self.pe.get_entrypoint_bytes(num_bytes=64)

        # FIXME: Assumes 32 bit, Github issue #6
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        location = None

        for isn in md.disasm(data, self.pe._pe.OPTIONAL_HEADER.ImageBase):

            # Once we've found a potential pointer we expect the next operand to be
            # a call (to SysInit).  If it's not a call we've found a dud file.
            if location:
                if isn.mnemonic != "call":
                    return None

                # TODO: Add a name hint to the overall program for SysInit function
                return location

            if isn.mnemonic != "mov":
                continue

            # Check the first operand is EAX, e.g. mov <REG>, 0x1234567
            if isn.operands[0].type != X86_OP_REG:
                continue

            if isn.reg_name(isn.operands[0].reg) != "eax":
                continue

            # Check the second operand is an immediate, not another register / memory
            if isn.operands[1].type != X86_OP_IMM:
                continue

            # Store and check the next operand is a call
            location = isn.operands[1].imm

        return None

    def parse_init_table(self, section, va, context):
        """
        Given a PE section and virtual address, parse the unit initialisation table and
        return it to the caller.  Returns None if there are errors parsing.
        """
        # TODO: Also pass the work queue here, so additional items can be
        #       added for parsing
        init_table = UnitTable(section, va, context=context)
        return init_table

    # TODO: Consider allowing only brute force mechanism, so the code can run without Capstone


class VersionHelper(Helper):

    # See: http://docwiki.embarcadero.com/RADStudio/Rio/en/Compiler_Versions
    versions = {
        # 1: { 'name': 'Delphi 1', 'ver': 'VER80' }, # No support for Delphi 1 or 2 in this tool
        # 2: { 'name': 'Delphi 2', 'ver': 'VER90' },
        3: {"name": "Delphi 3", "ver": "VER100"},
        4: {"name": "Delphi 4", "ver": "VER120"},
        5: {"name": "Delphi 5", "ver": "VER130"},
        6: {"name": "Delphi 6", "ver": "VER140"},
        7: {"name": "Delphi 7 / 7.1", "ver": "VER150"},
        # 8: { 'name': 'Delphi 8 for .Net', 'ver': 'VER160' }, # No .Net support in this tool
        9: {"name": "Delphi 2005", "ver": "VER170"},
        10: {"name": "Delphi 2006", "ver": "VER180"},
        11: {"name": "Delphi 2007", "ver": "VER185"},
        # 11: { 'name': 'Delphi 2007 for .Net', 'ver': 'VER190' },
        12: {"name": "Delphi 2009", "ver": "VER200"},
        # There is no version 13
        14: {"name": "Delphi 2010", "ver": "VER210"},
        15: {"name": "Delphi XE", "ver": "VER220"},
        16: {"name": "Delphi XE2", "ver": "VER230"},
        17: {"name": "Delphi XE3", "ver": "VER240"},
        18: {"name": "Delphi XE4", "ver": "VER250"},
        19: {"name": "Delphi XE5", "ver": "VER260"},
        20: {"name": "Delphi XE6", "ver": "VER270"},
        21: {"name": "Delphi XE7", "ver": "VER280"},
        22: {"name": "Delphi XE8", "ver": "VER290"},
        23: {"name": "Delphi 10 Seattle", "ver": "VER300"},
        24: {"name": "Delphi 10.1 Berlin", "ver": "VER310"},
        25: {"name": "Delphi 10.2 Tokyo", "ver": "VER320"},
        26: {"name": "Delphi 10.3 Rio", "ver": "VER330"},
    }
    minimum = None
    maximum = None

    def __init__(self, context):
        super().__init__()
        self._context = context
        self.minimum = 0
        self.maximum = 999
        self.guess_version()

    def guess_version(self):

        # TODO: Have all version checks return a dict from _select_versions(), so that
        #       we can compare at the end and ensure there are no outliers (e.g. one
        #       method says Delphi 3-5 and another says XE-XE4).

        # Length of the standard vftable (before class methods) varies depending
        # on Delphi version
        if self._context.header_length == 64:
            self._update_minimum(3)
            self._update_maximum(3)

        elif self._context.header_length == 76:
            self._update_minimum(4)
            self._update_maximum(11)

        elif self._context.header_length == 88:
            self._update_minimum(12)

        # Check section names
        # Early versions uses CODE for code section and DATA for data (confirmed to 2005)
        # Delphi 2006+ uses .text for code section
        if self._context.has_section(name=".text"):
            self._update_minimum(10)

        if self._context.has_section(name="CODE"):
            self._update_maximum(9)

        # Delayed import section, introduced with Delphi 2010
        # See: https://www.drbob42.com/examines/examinC1.htm
        if self._context.has_section(name=".didata"):
            self._update_minimum(14)

        # Check .rdata section for a compiler string, which seems to have been introduced
        # around XE7, which matches rules from Detect It Easy.
        rdata = self._context.get_section(".rdata")
        if rdata is None:
            self.logger.error(
                "Did not find a section named .rdata, this is not typical for Delphi"
            )
        else:
            # Example version string below, the first number inside the brackets
            # aligns to the versions used in pythia.
            #
            # Embarcadero Delphi for Win32 compiler version 28.0 (21.0.17707.5020)
            pattern = re.compile(
                b"Embarcadero Delphi for Win32 compiler version \d\d\.\d \((\d\d)\."
            )
            result = pattern.search(rdata.mapped_data)
            if result:
                version = int(result.group(1))
                self._update_minimum(version)
                self._update_maximum(version)
            else:
                # If there is no version string it must be Delphi XE6 or below
                self._update_maximum(20)

        names = []
        for s in self._context.code_sections:
            names.append(s.name)

        for s in self._context.data_sections:
            names.append(s.name)

        # Scan for "extra data" markers, which are part of many RTTI objects after
        # Delphi 10.  These come just before alignment padding, so we search for them
        # on 4 byte boundaries.  The actual bytes are:
        #  - 02 00  - 2 bytes of extra data (e.g. these two, no further data)
        #  - 8b c0  - alignment padding
        section = self._context.object_section
        found = 0
        i = 0
        while i < section.size - 4:
            section.stream_data.seek(i)
            (data,) = unpack_stream("I", section.stream_data)
            if data == 0xC08B0002:
                found += 1

            i += 4

        if found > 10:
            self._update_minimum(14)

        # TODO: Improve parsing of unit table so that it can be iterated, then
        #       look for things like SysInit to see when this was introduced
        # if self._context.units:
        #    self.logger.info(self._context.units)

        # Additional version detection strategies:
        #  - Size of various vftables / objects
        #  - "string" vs "String" (from DIE)

        # TODO: SHIFT THIS TO VERSION GUESSING CODE
        # Get crude Delphi version (<2010 or >=2010), which allows targeting of vftable search
        # strategy.  We check if the Unit Initialisation Table has a member named NumTypes,
        # which is the first of four extra fields introduced by Delphi 2010.
        #        try:
        #            num_types = init_table.fields["NumTypes"]
        #            self.logger.info("Executable seems to be generated by Delphi 2010+")
        #            modern_delphi = True
        #        except KeyError:
        #            modern_delphi = False
        #            self.logger.info("Executable seems to be generated by an earlier version of Delphi (pre 2010)")
        # END TODO

        # Check size of objects.  This scan is not intended to be complete,
        # and skips any data which fails validation.  More thorough scanning
        # is conducted later.
        self._select_versions(minimum=self.minimum, maximum=self.maximum)

    def _update_minimum(self, new):
        if new > self.minimum:
            self.minimum = new

    def _update_maximum(self, new):
        if new < self.maximum:
            self.maximum = new

    def _select_versions(self, minimum=0, maximum=999):
        """
        Select all items from the known version list that meet minimum / maximum
        criteria.
        """

        if minimum is 0 and maximum is 999:
            raise AttributeError("Need minimum or maximum")

        candidates = {}
        for ver, data in self.versions.items():
            if ver >= minimum and ver <= maximum:
                candidates[ver] = data

        self.logger.debug("returning candidate versions: {}".format(candidates))
        return candidates


class WorkQueue(Helper):
    def __init__(self):
        super().__init__()
        self._queue = []
        self._visited = set()

    def add_item(self, location, item_type):

        if location in self._visited:
            # This could cause problems if different types are found at the same location,
            # as the subsequent types will be ignored.  However, this should be a minor
            # problem with the current search strategy, unless the Vftable scanning
            # generates too many invalid locations.
            #
            # Other locations are added only if there is a pointer to them from another
            # validated object, so false positives should be minimal except the initial
            # vftable scan.
            #
            # TODO: Uncomment once better debug granularity is available
            # self.logger.debug(f"Location {location} has already been visited, not adding")
            return

        info = {"location": location, "item_type": item_type}
        self._queue.append(info)
        self._visited.add(location)

    def get_item(self, obj_type=None):

        # TODO: Investigate whether making this a generator would be more efficient, and if
        #       yield supports list modification during enumeration.

        # The caller can request a specific object type, e.g. to only parse
        # vftables without also parsing related objects.
        if obj_type:
            for i in range(0, len(self._queue)):
                if self._queue[i]["item_type"] == obj_type:
                    return self._queue.pop(i)

            return None

        # Otherwise return the first item in the list
        if self._queue:
            return self._queue.pop(0)

        return None
