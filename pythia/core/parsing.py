import io
import logging
import string
from collections import OrderedDict
from struct import unpack, calcsize
from prettytable import PrettyTable
from uuid import UUID
from .utils import extract_pascal_string, unpack_stream


class ValidationError(Exception):
    pass


class BaseParser:

    # TODO: Consider adding "relations", that can easily be enumerated
    # TODO: Refactor work queue into context, it's not relevant to the generic base class
    def __init__(self, stream, start_address=None, context=None, work_queue=None, parent=None):
        """

        :param stream:
        :param offset: the offset inside the stream, or None to use the current location
        :return:
        """

        self._init_logging()
        self.fields = OrderedDict()

        self.stream = stream
        self.context = context

        # If provided, parsers can append to the work queue, e.g. position & type of other items
        self.work_queue = work_queue

        # If no start address is passed, use the current position in the stream
        if start_address is None:
            start_address = stream.tell()

        self.start = start_address
        self.offset = start_address
        self.parent = parent
        self.related = {}
        self.embedded = []

        # Optional setup method to be called before parsing takes place. Split out here
        # in case future refactoring moves parse() from init.
        self._setup()

        # Needs to be implemented by concrete classes
        self.parse()

        # TODO: Check for alignment bytes, either 0x90 or 0x8BC0 or 0x8D4000.  Not all items are
        #       fully parsed, so can't do this here.  Might be better in utility scripts for IDA
        #       or Ghidra.  This will let us spot when additional data has not been parsed.

    def _setup(self):
        pass

    def _init_logging(self):
        """
        Initialise a logger with the name of this class, allowing finer control over which debug
        messages are suppressed.
        """
        name = f"{self.__module__}.{self.__class__.__qualname__}"
        self.logger = logging.getLogger(name)

    def stream_length(self):
        """
        Obtain the length of the underlying data stream.  This function will seek to obtain the
        length, but restores the current position.

        :return: length of self.stream (integer)
        """
        current_pos = self.stream.tell()
        self.stream.seek(0, io.SEEK_END)
        length = self.stream.tell()
        self.stream.seek(current_pos, io.SEEK_SET)

        return length

    def parse_field(self, format, name):
        self.parse_fields(format, [ name ])

    def parse_fields(self, format, names):

        # TODO: Take an optional start position - right now this assumes all reads are from the last position
        self.stream.seek(self.offset)

        # This does not allow numeric arguments, if these are required in
        # future the code will need updating.
        # TODO: Handling of C strings (zero terminated)
        valid = list("xB?HILQspGq")

        if not all(c in valid for c in format):
            raise ValueError("Invalid format string")

        # TODO: Validate the names are unique
        for name in names:
            if name in self.fields:
                raise ValueError(f"Key {name} already exists, can't add another with the same name")

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
                data = str(UUID(bytes_le=buf))

            elif f == "s":
                ascii_string = []
                raw_length = 0

                # TODO: Allow caller to specify max length and whether to pad
                while raw_length < 255:
                    raw_length += 1
                    buf = self.stream.read(1).decode("utf-8")

                    if buf == "\x00":
                        break
                    elif buf not in string.printable:
                        raise Exception("Found non-ASCII character in string")

                    ascii_string.append(buf)

                size = raw_length
                data = "".join(ascii_string)

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
        embedded = obj(
            self.stream, self.offset, self.context, self.work_queue, parent=self
        )

        # Add the object to fields
        size = len(embedded)
        self.add_field(name, embedded, None, self.offset, size)
        self.embedded.append(embedded)

        self.offset += size
        return embedded

    def embed_many(self, name_prefix, obj, count):

        i = 0
        while i < count:
            name = f"{name_prefix}[{i}]"
            self.embed(name, obj)
            i += 1

    def add_field(self, name, data, data_type, offset, size):
        data = {
            "name": name,
            "data": data,
            "type": data_type,
            "offset": offset,
            "size": size,
        }
        self.fields[name] = data

    def get_dump(self):
        items = []

        # TODO: Add depth, so embedded objects are indented one level below in the hierarchy

        for name, data in self.fields.items():
            # Check if data is derived from BaseParser and get additional
            # dump if necessary.
            if isinstance(data["data"], BaseParser):
                items += data["data"].get_dump()
            else:
                items.append(data)

        return items

    def __str__(self, offset=0):
        """
        Pretty print this object in a table, with an optional offset for the address (useful where
        the data processed is contained within another structure, such as a PE file).

        :param offset: optional adjustment for printed addresses
        :return: tablular data representing this object, as a string
        """
        table = PrettyTable()
        data = self.get_dump()

        table.field_names = ["Address", "Name", "Type", "Data", "Size"]
        for field in data:
            row = [
                "0x{:x}".format(field["offset"] + offset),
                field["name"],
                field["type"],
                field["data"],
                field["size"],
            ]
            table.add_row(row)

        return table.get_string()

    def __len__(self):
        """
        The length of an instance is the size (in bytes) of the fields it contains.

        :return: size of all contained fields
        """
        len = 0
        for _, data in self.fields.items():
            len += data["size"]

        return len

    # TODO: dump() method
    # TODO: pack() method to repack into bytes
