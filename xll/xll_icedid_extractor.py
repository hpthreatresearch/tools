#!/usr/bin/env python
# -*- coding: utf-8 -*-
# filename          : xll_icedid_extractor.py
# description       : Extracts IcedID from XLL file
# author            : @stoerchl
# email             : patrick.schlapfer@hp.com
# date              : 20220208
# version           : 1.0
# usage             : python xll_icedid_extractor.py -f <xll_file>
# license           : MIT
# py version        : 3.9.7
#==============================================================================

"""Extracts IcedID from XLL file
This simple scripts extracts the IcedID DLL from an XLL file and saves
the result to a file with the md5 hash as name.

Example:
    To execute the extraction script a IcedID-XLL file must be
    supplied as an argument.

        $ python xll_icedid_extractor.py -f 7c4913b7a8a3f5220aa46e8a044d17d2.xll

As threat actors constantly change their techniques this automation might not
work on future IcedID-XLL files. It should however provide a starting
point for implementing future extraction automations.
"""

import pefile
import binascii
import yara
import hashlib
import sys
import getopt
from pathlib import Path

xlcall32_icedid = """rule xlcall_icedid
{
    strings:
        $xlcall = "XLCall32"
        $sub_rsp = {  48 81 EC ?? ?? 00 00
                      48 8D 4C 24 20
                      41 B8 ?? ?? 00 00
                      48 8D 15 ?? ?? 00 00 }

        $mov_rax = {  48 89 05 ?? ?? 01 00
                      48 8D 54 24 20
                      48 89 05 ?? ?? 01 00
                      48 8B C8 }

        $lea_rbx = {  48 8D 98 ?? ?? 00 00
                      48 89 1D ?? ?? 01 00 }

        $lea_rcx = {  48 8D 0D ?? 3F 00 00
                      48 89 1D ?? ?? 01 00
                      48 81 C4 ?? ?? 00 00
                      5B }

        $dos_mode = { 44 4F 53 20 6D 6F 64 }

    condition:
        #dos_mode > 1 and all of them
}"""

def get_file_offset(addr):
    for section in pe.sections:
        if section.VirtualAddress < addr and addr < section.VirtualAddress + section.SizeOfRawData:
            offset = addr - section.VirtualAddress + section.PointerToRawData
            return offset

def get_virtual_offset(addr):
    for section in pe.sections:
        if section.PointerToRawData < addr and addr < section.PointerToRawData + section.SizeOfRawData:
            offset = addr + section.VirtualAddress - section.PointerToRawData
            return offset

def reverse_endian(addr_str):
    ret_addr = ""
    for x in range(len(addr_str), 0, -2):
        ret_addr += addr_str[x-2:x]
    return ret_addr

all_args = sys.argv[1:]

try:
    opts, arg = getopt.getopt(all_args, 'f:d:')
    if len(opts) != 1:
        print ('usage: \n\txll_icedid_extractor.py -f <xll_file>\n\txll_icedid_extractor.py -d <sample_folder>')
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
            pe = pefile.PE(xll_file)
            size = 0
            offset = 0

            with open(xll_file, "rb") as f:
                hexdata = binascii.hexlify(f.read())

            binary_data = b""

            rules = yara.compile(source=xlcall32_icedid)
            m = rules.match(xll_file)
            if len(m) > 0:
                for s in m[0].strings:
                    if s[1] == "$sub_rsp":
                      yara_offset = s[0]
                      size_offset = yara_offset*2+28
                      size = reverse_endian(hexdata[size_offset:size_offset+4].decode())
                      data_size = int(size, 16)

                      instruction_offset = yara_offset + 18
                      virtual_data_offset = reverse_endian(hexdata[instruction_offset*2+6:instruction_offset*2+10].decode())
                      v_instruction_offset = get_virtual_offset(instruction_offset + 7) # add instruction length of 7 bytes
                      virtual_data_addr = v_instruction_offset + int(virtual_data_offset, 16)
                      data_addr = get_file_offset(virtual_data_addr)

                      binary_data += hexdata[data_addr*2:data_addr*2+data_size*2]

                md5_hash = hashlib.md5(binascii.unhexlify(binary_data)).hexdigest()

                with open(md5_hash+'.dll', 'wb') as fout:
                    fout.write(
                        binascii.unhexlify(binary_data)
                        )

                print("[!] Done. Wrote: "+md5_hash+".dll")
            else:
                print("[!] This is not a IcedID-XLL")

except getopt.GetoptError:
    print ('usage: \n\txll_icedid_extractor.py -f <xll_file>\n\txll_icedid_extractor.py -d <sample_folder>')
    sys.exit(2)
except Exception as e:
    print(e)
