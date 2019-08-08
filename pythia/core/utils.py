import struct


def extract_pascal_string(stream, offset):
    """
    Obtain a Pascal string from a stream.

    :param stream:
    :param offset:
    :return:
    """

    # TODO: Error handling
    stream.seek(offset)
    (length,) = unpack_stream("B", stream)
    length += 1

    stream.seek(offset)
    (text,) = unpack_stream("{}p".format(length), stream)

    # Modern Delphi uses UTF8
    text = text.decode("utf8")

    # Return the raw length as UTF8 codepoints can be >1 byte
    return (text, length)


def unpack_stream(format, stream, offset=None):
    """
    Read from a stream using struct.unpack.

    :param format:
    :param stream:
    :return:
    """
    size = struct.calcsize(format)
    if offset is not None:
        stream.seek(offset)

    buf = stream.read(size)
    return struct.unpack(format, buf)