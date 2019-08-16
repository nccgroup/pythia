"""
Various helpers to provide utility functions which can also be used from other code.
"""
import logging
import pefile
from binascii import unhexlify
from capstone import *
from capstone.x86 import *
from .structures import packageinfo
from .objects import UnitTable

class Helper(object):
    def __init__(self):
        self._init_logging()

    def _init_logging(self):
        """
        Initialise a logger with the name of this class, allowing finer control over which debug
        messages are suppressed.
        """
        name = f'{self.__module__}.{self.__class__.__qualname__}'
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
        data = self._pe.get_memory_mapped_image()[ep:ep+num_bytes]
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

    def parse_init_table(self, section, va, delphi_program):
        """
        Given a PE section and virtual address, parse the unit initialisation table and
        return it to the caller.  Returns None if there are errors parsing.
        """
        # TODO: Also pass the work queue here, so additional items can be
        #       added for parsing
        init_table = UnitTable(section, va, delphi_program=delphi_program)

        self.logger.debug(init_table)
        return init_table

    # TODO: Consider allowing only brute force mechanism, so the code can run without Capstone


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
            # Other locationds are added only if there is a pointer to them from another
            # validated object, so false positives should be minimal except the initial
            # vftable scan.
            #
            # TODO: Uncomment once better debug granularity is available
            #self.logger.debug(f"Location {location} has already been visited, not adding")
            return

        info = { "location": location, "item_type": item_type }
        self._queue.append(info)
        self._visited.add(location)

    def get_item(self):

        # TODO: Investigate whether making this a generator would be more efficient, and if
        #       yield supports list modification during enumeration.
        if self._queue:
            return self._queue.pop(0)

        return None
