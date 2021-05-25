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
    
    print("[[bibliography]]")
    print("== Bibliography")
    print("// Parsed from %s" % bibtex_input)
    print("")

    parsed = parse_bibtex(bibtex_input)
    for entry_name in parsed.entries:
        entry = parsed.entries[entry_name]
        elements = []

        ef  = entry.fields

        elements.append(ef.get("title",""))
        elements.append(ef.get("author","")) # todo
        elements.append(ef.get("publisher",""))
        elements.append(ef.get("organization",""))
        elements.append(ef.get("journal",""))
        elements.append(ef.get("booktitle",""))
        elements.append(ef.get("howpublished",""))
        elements.append(ef.get("pages",""))
        elements.append(ef.get("volume",""))
        elements.append(ef.get("month",""))
        elements.append(ef.get("year",""))
        elements.append(ef.get("url","").lstrip(" ,"))
        elements.append(ef.get("note",""))
        elements.append(ef.get("doi",""))

        elements = [e for e in elements if e != ""]

        sanitised = []
        for e in elements:
            ne = e.replace("\\url{","")
            ne = ne.replace("{","")
            ne = ne.replace("}","")
            ne = ne.strip()
            sanitised.append(ne)
        elements = sanitised

        contents = ", ".join(elements)
        op = "* [[[%s]]] %s" % (entry_name.replace("+",":"), contents)
        print(op)


if "__main__" == __name__:
    main()

