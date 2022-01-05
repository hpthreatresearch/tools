#!/usr/bin/env python
# -*- coding: utf-8 -*-
# filename          : decode.py
# description       : Extracts URLs from Gootloader JavaScript
# author            : @stoerchl
# email             : patrick.schlapfer@hp.com
# date              : 20220105
# version           : 2.1
# usage             : python decode.py -d <directory_to_search>
# license           : MIT
# py version        : 3.9.1
#==============================================================================

"""Gootloader decoder and URL extractor

This module tries to deobfuscate Gootloader JavaScript and extract its next stage
URLs. Gootloader is a JavaScript downloader which is known to download either
Gootkit or REvil ransomware. As this seems to be a newer downloader script which
became active in late 2020 we didn't find a name and therefore called it Gootloader
(https://twitter.com/HP_Bromium/status/1362789106481328128).

Example:
            To execute the decoding script a folder containing the
            Gootloader script must be supplied as an argument.

                $ python decode.py -d samples/20210222/

As threat actors constantly change their techniques this automation might not
work on future Gootloader scripts. It should however provide a starting
point for implementing future decoding automations.

"""

import re
import getopt
import sys
import warnings
from codecs import encode, decode
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning)

functions_regex = r"\w+\[\d{7}\]=\w+;\s*\w+=.+$"
code_regex = r"(?<!\\)(?:\\\\)*'([^'\\]*(?:\\.[^'\\]*)*)'"
ext_code_regex = r"(\w+)\s*=\s*(?<!\\)(?:\\\\)*'([^'\\]*(?:\\.[^'\\]*)*)'"
code_order = r"\=\s*((?:\w+\+){NUM_REP}(?:\w+));"
breacket_regex = "\[(.*?)\]"
url_regex = "(?:https?:\/\/[^=]*)"
separator_regex = "([\'|\"].*?[\'|\"])"

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
    opts, arg = getopt.getopt(all_args, 'd:')
    if len(opts) != 1:
        print ('usage: decode.py -d <directory_to_search>')
    else:
        opt, arg_val = opts[0]
        all_domains = set()
        all_urls = set()
        all_files = sorted(list(Path(arg_val).rglob("*")))
        for f in all_files:
            try:
                js = open(f)
                content = js.read()
                
                if len(content) > 100000: # new version. file contains library code to obfuscate
                    clean_content = ""
                    matches = re.findall(functions_regex, content, re.MULTILINE)
                    for m in matches:
                        clean_content += m + "\n"

                    matches = re.findall(ext_code_regex, clean_content, re.MULTILINE)
                    code_parts = dict()
                    for m in matches:
                        code_parts[m[0]] = m[1]
                    
                    matches = re.findall(code_order.replace("NUM_REP", str(len(code_parts)-1)), clean_content, re.MULTILINE)
                    order = list()
                    for m in matches:
                        order = m.split("+")
                        
                    ordered_code = ""
                    for element in order:
                        ordered_code += code_parts[element]
                    content = "'" + ordered_code + "'"
                    
                round = 0
                while round < 2:
                    matches = re.findall(code_regex, content, re.MULTILINE)
                    longest_match = ""
                    for m in matches:
                        if len(longest_match) < len(m):
                            longest_match = m
                    
                    content = decode_cipher(decode(encode(longest_match, 'latin-1', 'backslashreplace'), 'unicode-escape')) #
                    round += 1

                domains = re.findall(breacket_regex, content.split(";")[0], re.MULTILINE)
                urls = re.findall(url_regex, content, re.MULTILINE)
                if len(urls) > 0:
                    replaceables = re.findall(separator_regex, urls[0], re.MULTILINE)
                    if len(replaceables) == 2:
                        for d in domains:
                            for dom in d.replace("\"", "").replace("'", "").split(","):
                                all_domains.add(dom)
                                all_urls.add(urls[0].replace(replaceables[0], dom).replace(replaceables[1], "") + "=")
                                
                    print("OK - " + str(f))
                else:
                    print("NOK - " + str(f))
                    
            except Exception as e:
                print(e)
                print("ERROR - Could not decode Gootloader - " + str(f))

        print("Found URLs: (" + str(len(all_urls)) + ")")
        w = open("urls.txt", "a")
        for url in all_urls:
            w.write(url + "\n")
        w.close()
        print("> Wrote file: urls.txt")

        print("Found Domains: (" + str(len(all_domains)) + ")")
        w = open("domains.txt", "a")
        for domain in all_domains:
            w.write(domain + "\n")
        w.close()
        print("> Wrote file: domains.txt")

except getopt.GetoptError:
    print ('usage: decode.py -d <directory_to_search>')
    sys.exit(2)
