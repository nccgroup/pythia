# vim: autoindent expandtab tabstop=4 shiftwidth=4 softtabstop=4
# filetype=python

import argparse
import json
from . import VERSION_STRING
from .core import DelphiParser


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
        "-p",
        "--profile",
        type=str,
        help="set the version of Delphi (default: auto)",
        default="auto",
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

    engine = DelphiParser(filename=args.file, debug=args.verbose)

    # TODO: Add Delphi version etc.
    info = {
        "creator": "pythia, a python tool to parse information from Delphi executables",
        "pythia_version": VERSION_STRING,
        "profile": args.profile,
        # "image_base": pe.OPTIONAL_HEADER.ImageBase
    }

    # TODO: Fixme output
    total_found = 0
    total_embedded = 0

    items = []
    for item in engine.results.items:
        if item.is_embedded:
            total_embedded += 1
        else:
            items += item.get_dump()
            total_found += 1

    print(f"Found {total_found} items and {total_embedded} embedded items")

    output = {"info": info, "items": items}

    # TODO: Wrap the output with some data about the input file
    with open("output.json", "w") as fh:
       fh.write(json.dumps(output))


if __name__ == "__main__":
    main()
