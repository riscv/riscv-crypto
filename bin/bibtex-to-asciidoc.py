#!/usr/bin/python3

import os
import sys

# You will need to install this library:
# > pip3 install pybtex
from pybtex.database import parse_file as parse_bibtex

def main():
    """
    Main function for the script.
    """
    bibtex_input = sys.argv[1]
    print("Parsing %s" % bibtex_input)

    parsed = parse_bibtex(bibtex_input)
    for entry_name in parsed.entries:
        entry = parsed.entries[entry_name]
        elements = []

        elements.append(entry.fields.get("title",""))
        elements.append(entry.fields.get("author","")) # todo
        elements.append(entry.fields.get("publisher",""))
        elements.append(entry.fields.get("organization",""))
        elements.append(entry.fields.get("journal",""))
        elements.append(entry.fields.get("booktitle",""))
        elements.append(entry.fields.get("howpublished",""))
        elements.append(entry.fields.get("pages",""))
        elements.append(entry.fields.get("volume",""))
        elements.append(entry.fields.get("month",""))
        elements.append(entry.fields.get("year",""))
        elements.append(entry.fields.get("url","").lstrip(" ,"))
        elements.append(entry.fields.get("note",""))
        elements.append(entry.fields.get("doi",""))

        elements = [e for e in elements if e != ""]
        contents = ", ".join(elements)
        op = "* [[[%s]]] %s" % (entry_name, contents)
        print(op)


if "__main__" == __name__:
    main()

