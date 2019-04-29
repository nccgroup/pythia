from struct import unpack, calcsize

class ValidationError(Exception):
    pass


class Section:
    # TODO: Needs a start, end, name
    pass


class Base:

    def __init__(self, stream, start=None):
        """

        :param stream:
        :param offset: the offset inside the stream, or None to use the current location
        :return:
        """

        self.fields = []
        self.stream = stream
        self.start = start
        self.offset = start

    def get_fields(self, format, names):

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
        # TODO: Add offset & potentially length?
        field = { 'name': name, 'data': data, 'type': data_type }
        print(field)
        self.fields.append(field)

    # TODO: dump() method
    # TODO: pack() method to repack into bytes


class Vftable(Base):

    def __init__(self, stream, offset=None):
        super().__init__(stream, offset)
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

        self.get_fields("IIIIIIIIIII", common)
