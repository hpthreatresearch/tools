#!/usr/bin/env python
# -*- coding: utf-8 -*-
# filename          : unpacker.py
# description       : Tries to unpack Hancitor DLL and extract C2 URLs 
# author            : @stoerchl 
# email             : patrick.schlapfer@hp.com 
# date              : 20210223 
# version           : 1.0 
# usage             : python unpacker.py -f <hancitor_dll> 
# license           : MIT 
# py version        : 3.9.1 
#==============================================================================

"""Hancitor unpacker and URL extractor.

This module tries to unpack a Hancitor DLL using the methods described in the accompanying 
HP Threat Research blog post. The unpacking is done in multiple stages. The output of 
stage 2 is the unpacked sample, and the output of stage 3 are the C2 URLs which are used 
by Hancitor to download further payloads.

Example:
            To execute the unpacker script, a Hancitor DLL must be supplied
            as an argument.

                $ python unpacker.py -f samples/20210223/hancitor.dll

Since Hancitor seems to use several packer variations, unfortunately not all Hancitor DLLs
can be unpacked successfully. The unpacking key changes from time to time, so the unpacker 
tries to find the key using brute force, which is not ideal. Due to the limited key space, 
unpacking is still possible, just does not scale optimally.

Todo:
            * Adapt unpacker to support more packer variants.
            * Improve unpacking performance

"""

import os
import sys
import binascii
import pefile
import getopt
import subprocess
from wincrypto import CryptCreateHash, CryptHashData, CryptDeriveKey, CryptDecrypt
from wincrypto.constants import CALG_SHA1, CALG_RC4

all_args = sys.argv[1:]

def switch_endian(value):
    ret = ""
    for j in range(len(value), 0, -2):
        ret += value[j-2:j]
    return ret

def xor_strings(string1, string2):
    ret_val = format(int(string1, 16) ^ int(string2, 16), "x")
    return ret_val.zfill(8)


try:
    opts, arg = getopt.getopt(all_args, 'f:')
    if len(opts) != 1:
        print ('usage: unpacker.py -f <packed_hancitor_binary>')
        sys.exit(2)
    else:
        opt, arg_val = opts[0]
        stage1_file = arg_val

except getopt.GetoptError:
    print ('usage: unpacker.py -f <packed_hancitor_binary>')
    sys.exit(2)


###########################
## Stage 1 Decryption
###########################
print("------------------------")
print("# Trying to unpack file: " + str(stage1_file) + "\n")
print("# Starting Stage 1")

plaintext = ""
stage2_file = ""
stage3_file = ""
dos_str = b"This program cannot be run in DOS mode"

found_potential_section = False
pe = pefile.PE(stage1_file)
default_sections = [".text", ".bss", ".rdata", ".data", ".rsrc", ".edata", ".idata", ".pdata", ".debug", ".reloc", "o"]
for section in pe.sections:
    if found_potential_section:
        break

    plaintext = ""
    skip_section = False
    # decryption_key = 0xD508 # At the following addresses the key is constructed: 0x100458B6 and 0x100458FD
    section_name = str(section.Name.decode().rstrip('\x00'))
    if section_name not in default_sections:
        process = subprocess.Popen("dd if=" + stage1_file + " of=" + stage1_file + section_name + " bs=1 skip=" + str(section.PointerToRawData) + " count=" + str(section.Misc_VirtualSize) + " status=none", shell=True, stdout=subprocess.PIPE)
        process.wait()
        if process.returncode == 0:
            file_size = os.path.getsize(stage1_file + section_name)
            for i in range(256, 65535):
                if skip_section:
                    break

                decryption_key = i
                plaintext = ""
                with open(stage1_file + section_name, "rb") as f:
                    offset = 0
                    allocation_size = 0
                    dword = b''
                    skip = True
                    while (byte := f.read(1)):
                        dword += byte
                        if dword == b'!!':
                            dword = b''
                            continue

                        if len(dword) == 4:
                            if skip:
                                allocation_size = int(switch_endian(binascii.hexlify(dword).decode()), 16)
                                if allocation_size > file_size:
                                    skip_section = True
                                    break

                                skip = False
                                dword = b''
                            else:
                                converted_dword = int.from_bytes(dword, "little")
                                converted_dword = converted_dword + 0x4 * (offset)
                                plaintext += switch_endian(xor_strings(hex(converted_dword), hex(decryption_key)))
                                dword = b''
                                decryption_key = decryption_key + 0x4
                                offset += 1

                                if offset * 4 > allocation_size:
                                    break

                                if offset * 4 > 150:
                                    binstr = binascii.unhexlify(plaintext)
                                    if b"VirtualAlloc" not in binstr:
                                        break
                try:
                    binstr = binascii.unhexlify(plaintext)
                    if b"VirtualAlloc" in binstr and b"VirtualProtect" in binstr:
                        stage2_file = stage1_file + section_name + '_decoded.bin'
                        f = open(stage2_file, 'wb')
                        f.write(binstr)
                        f.close()
                        print("# - The Key is: " + str(hex(i)))
                        print("# - Wrote file: " + stage2_file)
                        found_potential_section = True
                        break
                except:
                    pass


if stage2_file == "":

    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            offset = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            break
        break
    malcfgData = pe.get_memory_mapped_image()[offset+4:offset+size]
    f = open(stage1_file + "_resource", 'wb')
    f.write(malcfgData)
    f.close()
    for i in range(256, 1048575):
        if skip_section:
            break

        decryption_key = i
        plaintext = ""
        with open(stage1_file + "_resource", "rb") as f:
            offset = 0
            allocation_size = size-4
            dword = b''
            skip = False
            while (byte := f.read(1)):
                dword += byte
                if dword == b'!!':
                    dword = b''
                    continue

                if len(dword) == 4:
                    converted_dword = int.from_bytes(dword, "little")
                    converted_dword = converted_dword + 0x4 * (offset)
                    plaintext += switch_endian(xor_strings(hex(converted_dword), hex(decryption_key)))
                    dword = b''
                    decryption_key = decryption_key + 0x4
                    offset += 1

                    if offset * 4 > allocation_size:
                        break

                    if offset * 4 > 150:
                        binstr = binascii.unhexlify(plaintext)
                        if b"VirtualAlloc" not in binstr:
                            break
        try:
            binstr = binascii.unhexlify(plaintext)
            if b"VirtualAlloc" in binstr and b"VirtualProtect" in binstr:
                stage2_file = stage1_file + "_resource" + '_decoded.bin'
                f = open(stage2_file, 'wb')
                f.write(binstr)
                f.close()
                print("# - The Key is: " + str(hex(i)))
                print("# - Wrote file: " + stage2_file)
                found_potential_section = True
                break
        except:
            pass

    if stage2_file == "":
        print("# ERROR in Stage 1")
        print("------------------------\n")
        sys.exit(2)
    else:
        print("# Successfully finished Stage 1\n")
else:
    print("# Successfully finished Stage 1\n")


###########################
## Stage 2 Decryption
###########################

print("# Starting Stage 2")

try:
    contents = None
    with open(stage2_file, 'rb') as f:
        contents = f.read()

    start_offset = contents.find(b"FreeLibrary") + 11
    max_search = 0x200
    binary_offset = 0

    for i in range(start_offset, len(contents), 4):
        data_length = int(switch_endian(binascii.hexlify(contents[i:i+4]).decode()), 16)
        if data_length > 1024:
            binary_offset = i + 4
            break

    encrypted_binary = contents[binary_offset:(binary_offset + data_length)]
    binary_encrypted = True

    try:
        stage3_file_check = pefile.PE(data=encrypted_binary)
        stage3_file = stage1_file + "_unpacked.bin"
        f = open(stage3_file, 'wb')
        f.write(encrypted_binary)
        f.close()
        binary_encrypted = False
    except Exception as ex:
        pass

    if binary_encrypted:
        for j in range(256, 65535):
            decryption_key = j
            plaintext = ""
            counter = 0

            for i in range(0, len(encrypted_binary), 4):
                converted_dword = int.from_bytes(encrypted_binary[i:i+4], "little")
                converted_dword = converted_dword + 0x4 * counter
                plaintext += switch_endian(xor_strings(hex(converted_dword), hex(decryption_key)))
                decryption_key = decryption_key + 0x4
                counter += 1

                if i > 120:
                    binstr = binascii.unhexlify(plaintext)
                    if dos_str not in binstr:
                        break

            binstr = binascii.unhexlify(plaintext)
            if dos_str in binstr:
                print("# - The Key is: " + hex(j))
                stage3_file = stage1_file + "_unpacked.bin"
                f = open(stage3_file, 'wb')
                f.write(binstr)
                f.close()
                break

except Exception as e:
    print(e)
    print("# ERROR in Stage 2")
    print("------------------------\n")
    sys.exit(2)

print("# - Wrote file: " + stage3_file)
print("# Successfully finished Stage 2\n")

###########################
## URL and Build Extraction
###########################

print("# Starting Stage 3")

try:
    pe = pefile.PE(stage3_file)
    for section in pe.sections:
        section_name = str(section.Name.decode().rstrip('\x00'))
        if section_name == ".data":
            data = section.get_data()
            sha1_hasher = CryptCreateHash(CALG_SHA1)
            CryptHashData(sha1_hasher, data[16:24]) # static offset. Address 0x10005010
            rc4_key = CryptDeriveKey(sha1_hasher, CALG_RC4)
            rc4_key.key = rc4_key.key[:5]
            plain_data = CryptDecrypt(rc4_key, data[24:8216]) # right after the hashed data with length 0x2000
            data_table = plain_data.split(b"\x00")
            for e in data_table:
                decoded_data = e.decode()
                if decoded_data != "":
                    if "|" in decoded_data:
                        print("# - Hancitor URLs: [" + ", ".join(decoded_data.split("|")[:-1]) + "]")

                    else:
                        print("# - Hancitor Build: "  + decoded_data)
except:
    print("# ERROR in Stage 3")
    print("------------------------\n")
    sys.exit(2)

print("# Successfully finished Stage 3")
print("------------------------\n")
