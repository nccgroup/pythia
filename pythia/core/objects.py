import io
import logging
from collections import OrderedDict
from struct import unpack, calcsize
from .utils import *


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
        if va > self.load_address and va < self.load_address + self.size:
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

    def __init__(self, stream, section, start=None):
        """

        :param stream:
        :param offset: the offset inside the stream, or None to use the current location
        :return:
        """

        # TODO: Initialise a logger with the module name

        # TODO: Fields could be an OrderedDict?
        self.fields = OrderedDict()
        self.stream = stream
        self.section = section
        self.start = start
        self.offset = start

    def parse_fields(self, format, names):

        # TODO: Take an optional start position - right now this assumes all reads are from the last position

        # This does not allow numeric arguments, if these are required in
        # future the code will need updating.
        # TODO: Would this be better at class level?  Test performance
        # TODO: Handling of strings (Pascal and zero terminated)
        valid = list("xB?HILQsp")

        if not all(c in valid for c in format):
            raise ValueError("Invalid format string")

        if len(format) != len(names):
            raise ValueError("Format string length and number of names should match")

        i = 0

        #  This assumes single byte format specifiers (no numbers)
        for f in format:
            length = calcsize(f)

            # TODO: Error handling on .read()
            buf = self.stream.read(length)
            self.offset += length

            (data,) = unpack(f, buf)
            self.add_field(names[i], data, f)
            i += 1

    def add_field(self, name, data, data_type):
        # TODO: Add offset & length
        data = { 'data': data, 'type': data_type }
        self.fields[name] = data

    # TODO: dump() method
    # TODO: pack() method to repack into bytes


class Vftable(BaseParser):

    # TODO: Take an argument for which profile matches (legacy vs. modern Delphi)
    def __init__(self, stream, section, offset=None):
        super().__init__(stream, section, offset)
        self.parse()

    def parse(self):
        common = [
            "vmtSelfPtr",
            "vmtIntfTable",
            "vmtAutoTable",
            "vmtInitTable",
            "vmtTypeInfo",
            "vmtFieldTable",
            "vmtMethodTable",
            "vmtDynamicTable",
            "vmtClassName",
            "vmtInstanceSize",
            "vmtParent",
        ]

        self.parse_fields("IIIIIIIIIII", common)

        # A number of checks to ensure our brute force method has found a valid
        # vftable.  Note that legitimate code produced by the Delphi compiler
        # will often include unrelated sequences of bytes which aren't vftables
        # but pass basic checks.  Therefore this should be robust enough to
        # reject them.
        self._validate_headers()

        # Extract the class name
        name_offset = self.section.offset_from_va(self.fields["vmtClassName"]["data"])
        self.name = extract_pascal_string(self.stream, name_offset)

        # TODO: Validate name
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

        ignore = ["vmtInstanceSize", "vmtSelfPtr"]

        for name,info in self.fields.items():
            if name.startswith("vmt") and name not in ignore:
                if info['data'] and not self.section.contains_va(info['data']):
                    raise ValidationError("Field {} data points outside the code section".format(name))

        if self.fields["vmtInstanceSize"]["data"] > 1024 * 500:
            raise ValidationError("Improbably large vmtInstanceSize {}".format(self.fields["vmtInstanceSize"]["data"]))

        return True
