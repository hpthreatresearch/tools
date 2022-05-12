#!/usr/bin/env python
# -*- coding: utf-8 -*-
# filename          : decode_webredraw.py
# description       : Extracts URLs from website redraw script
# author            : @stoerchl
# email             : patrick.schlapfer@hp.com
# date              : 20220505
# version           : 1.0
# usage             : decode_webredraw.py -d <directory_to_search>
# license           : MIT
# py version        : 3.9.1
#==============================================================================

"""Decoder for GootLoader webdraw script

This module tries to deobfuscate Gootloader's web redraw script which makes
the website look like a forum. The web redraw script also contains the next 
stage download URL which is extracted by this decoder.

Example:
            To execute the decoding script a folder containing the
            Gootloader web redraw script must be supplied as an argument.

                $ python decode_webredraw.py -d samples/20210506/

As threat actors constantly change their techniques this automation might not
work on future Gootloader scripts. It should however provide a starting
point for implementing future decoding automations.

"""

import re
import getopt
import sys
from pathlib import Path

html_regex = r"'(.*)'\s*\)?\s*;"
url_regex = "(https?:\/\/[^\"]*)"

all_args = sys.argv[1:]

def decode_cipher(cipher):
    plaintext = ""
    counter = 0
    while(counter < len(cipher)):
        decoded_char = cipher[counter]
        if counter % 2:
            plaintext = plaintext + decoded_char
        else:
            plaintext = decoded_char + plaintext
        counter += 1
    return plaintext

try:
    all_urls = set()
    opts, arg = getopt.getopt(all_args, 'd:')
    if len(opts) < 1:
        print ('usage: decode_webredraw.py -d <directory_to_search>')
    else:
        for opt, arg_val in opts:
            if opt == "-d":
                folder = Path(arg_val)

            if folder == None or not folder.is_dir():
                print ('usage: decode_webredraw.py -d <directory_to_search>')
                sys.exit(2)

            all_files = sorted(list(folder.rglob("*")))
            for f in all_files:
                content = None
                try:
                    with open(f, encoding="utf16", errors='ignore') as infile:
                        content = infile.read()
                except:
                    pass # Reading with utf16 did not work.

                try:
                    if not content:
                        with open(f, encoding="utf8", errors='ignore') as infile:
                            content = infile.read()

                    code_content = None
                    match = re.findall(html_regex, content.replace("\'+\'", ""), re.MULTILINE)
                    if len(match) > 0:
                        code_content = decode_cipher(match[0])

                    if code_content:
                        urls = re.findall(url_regex, code_content, re.MULTILINE)
                        all_urls.update(urls)

                    print("OK - " + str(f))
                except:
                    print("NOK - " + str(f))
                
            print("Found URLs: (" + str(len(all_urls)) + ")")
            w = open("urls.txt", "a")
            for url in all_urls:
                w.write(url + "\n")
            w.close()
            print("> Wrote file: urls.txt")

except getopt.GetoptError:
    print ('usage: decode_webredraw.py -d <directory_to_search>')
    sys.exit(2)
except Exception as e:
    print(e)
