#!/usr/bin/env python
# -*- coding: utf-8 -*-
# filename          : xll_baza_extractor.py
# description       : Extracts BazaLoader from XLL file
# author            : @stoerchl
# email             : patrick.schlapfer@hp.com
# date              : 20220208
# version           : 1.0
# usage             : python xll_baza_extractor.py -f <xll_file>
# license           : MIT
# py version        : 3.9.7
#==============================================================================

"""Extracts BazaLoader from XLL file
This simple scripts extracts the BazaLaoder DLL from an XLL file and saves
the result to a file with the md5 hash as name.

Example:
    To execute the extraction script a Baza-XLL file or a folder must be
    supplied as an argument.

        $ python xll_baza_extractor.py -f 06e70aab2069b7c471f4cd3d70ba3829.xll
        $ python xll_baza_extractor.py -d samples/

As threat actors constantly change their techniques this automation might not
work on future Baza-XLL files. It should however provide a starting
point for implementing future extraction automations.
"""

import yara
import binascii
import re
import getopt
import sys
import hashlib
from pathlib import Path

reg1 = "c64424[0-9a-f]{2}([0-9a-f]{2})"
reg2 = "c68424[0-9a-f]{4}0000([0-9a-f]{2})"

xlcall32_baza = """rule xlcall32_baza
{
    strings:
	   $xlcall = "XLCall32"
       $mzheader1 = { 	C6 44 24 ?? 4D
			C6 44 24 ?? 5A
			C6 44 24 ?? 90
			C6 44 24 ?? 00 }

       $mzheader2 = { 	C6 84 24 ?? 00 00 00 4D
			C6 84 24 ?? 00 00 00 5A
			C6 84 24 ?? 00 00 00 90
			C6 84 24 ?? 00 00 00 00 }

       $dosmode1 = { 	C6 44 24 ?? 44
			C6 44 24 ?? 4f
			C6 44 24 ?? 53
			C6 44 24 ?? 20
			C6 44 24 ?? 6d
			C6 44 24 ?? 6f
			C6 44 24 ?? 64
			C6 44 24 ?? 65 }

       $dosmode2 = { 	C6 84 24 ?? 00 00 00 44
			C6 84 24 ?? 00 00 00 4f
			C6 84 24 ?? 00 00 00 53
			C6 84 24 ?? 00 00 00 20
			C6 84 24 ?? 00 00 00 6d
			C6 84 24 ?? 00 00 00 6f
			C6 84 24 ?? 00 00 00 64
			C6 84 24 ?? 00 00 00 65 }

    condition:
        any of ($mzheader*) and any of ($dosmode*) and $xlcall
}"""

all_args = sys.argv[1:]

try:
    opts, arg = getopt.getopt(all_args, 'f:d:')
    if len(opts) != 1:
        print ('usage: \n\txll_baza_extractor.py -f <xll_file>\n\txll_baza_extractor.py -d <sample_folder>')
    else:
        opt, arg_val = opts[0]
        files = list()

        if opt == "-d":
            all_files = sorted(list(Path(arg_val).rglob("*")))
            for f in all_files:
                files.append(str(f))
        else:
            files.append(arg_val)

        for xll_file in files:
            rules = yara.compile(source=xlcall32_baza)
            m = rules.match(xll_file)
            data = dict()

            if len(m) > 0:
                with open(xll_file, 'rb') as f:
                    hexdata = binascii.hexlify(f.read())

                mz_offset = m[0].strings[1][0]
                binary_in_hex = hexdata[mz_offset*2:]

                for m in re.finditer(reg1, binary_in_hex.decode()):
                    data[m.start()] = m.group(1)

                for m in re.finditer(reg2, binary_in_hex.decode()):
                    data[m.start()] = m.group(1)

                sorted_data = dict(sorted(data.items()))

                hex_str = ""
                for k in sorted_data:
                    hex_str += sorted_data[k]

                md5_hash = hashlib.md5(binascii.unhexlify(hex_str)).hexdigest()

                with open(md5_hash+'.dll', 'wb') as fout:
                    fout.write(
                        binascii.unhexlify(hex_str)
                    )
                print("[!] Done. Wrote: "+md5_hash+".dll")
            else:
                print("[!] This is not a Baza-XLL")

except getopt.GetoptError:
    print ('usage: \n\txll_baza_extractor.py -f <xll_file>\n\txll_baza_extractor.py -d <sample_folder>')
    sys.exit(2)
except Exception as e:
    print(e)
