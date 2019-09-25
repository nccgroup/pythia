# vim: autoindent expandtab tabstop=4 shiftwidth=4 softtabstop=4
# filetype=python

import argparse
import json
from . import VERSION_STRING
from .core import DelphiParser

class TextEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return str(obj)

        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def main():
    # TODO: Move into class
    # config = load_config()

    # TODO: Argparse
    description = (
        "Parse compiled Delphi apps and retrieve RTTI.\n"
        "This is pythia version {}.".format(VERSION_STRING)
    )

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="set the version of Delphi (default: <input>-pythia.json)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="print more messages, use twice for maximum verbosity",
        default=0,
        action="count",
    )
    parser.add_argument("file", help="portable executable file to process")
    args = parser.parse_args()

    # TODO: Catch exceptions and output an error
    engine = DelphiParser(filename=args.file, debug=args.verbose)

    # TODO: Add Delphi version etc.
    info = {
        "creator": "pythia, a python tool to parse information from Delphi executables",
        "pythia_version": VERSION_STRING,
        # "image_base": pe.OPTIONAL_HEADER.ImageBase
    }

    # TODO: Fixme output
    total_found = 0
    total_embedded = 0

    items = []

    for item in engine.program.items:
        items += item.get_dump()
        total_found += 1

    print(f"Found {total_found} items")

    output = {"info": info, "items": items, "name_hints": engine.program.name_hints}

    if args.output is None:
        args.output = "{}-pythia.json".format(args.file)

    # TODO: Wrap the output with some data about the input file
    with open(args.output, "w") as fh:
       fh.write(json.dumps(output, cls=TextEncoder))


if __name__ == "__main__":
    main()
