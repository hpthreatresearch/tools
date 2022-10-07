#!/usr/bin/env python
# -*- coding: utf-8 -*-
# filename          : decode.py
# description       : Extracts URLs from Gootloader JavaScript
# author            : @stoerchl
# email             : patrick.schlapfer@hp.com
# date              : 20221007
# version           : 2.7
# usage             : decode.py -d <directory_to_search> [-o <output_directory>] [-r]
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

            Additional arguments can be added to dump the decoded
            GootLoader script as well as to execute a recursive 
            search through the provided directory.

            Recursive search:
                $ python decode.py -d samples/20220405/ -r

            Dump decoded scripts:
                $ python decode.py -d samples/20220405/ -o decoded_scripts/

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

functions_regex = r".*\s*\w+\[\d{7}\]=\w+;(?:\s*\w+=\d+;)?\s*.*$"
code_regex = r"(?<!\\)(?:\\\\)*'([^'\\]*(?:\\.[^'\\]*)*)'"
ext_code_regex = r"(\w+)\s*=\s*(?<!\\)(?:\\\\)*'([^'\\]*(?:\\.[^'\\]*)*)'"
code_order = r"\=\s*((?:\w+\+){NUM_REP}(?:\w+));"
re_code_order = r"(\w+\s*\=\s*(?:\w+\+?)+(?:\w+));"
breacket_regex = "\[(.*?)\]"
url_regex = "(?:https?:\/\/[^=]*)"
separator_regex = "([\'|\"].*?[\'|\"])"
array_replace_regex = "\w\[\w\]"

var_regex = r"(\w+)\=\'(.*)\';$"
func_regex = r"^(\w+)\s*\=\s*((?:\w+\+){1,}\w+);"


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
    opts, arg = getopt.getopt(all_args, 'd:ro:')
    if len(opts) < 1:
        print ('usage: decode.py -d <directory_to_search> [-o <output_directory>] [-r]')
    else:
        folder = None
        recursive = False
        output_folder = None
        for opt, arg_val in opts:
            if opt == "-d":
                folder = Path(arg_val)
            elif opt == "-r":
                recursive = True
            elif opt == "-o":
                output_folder = Path(arg_val)
                output_folder.mkdir(parents=False, exist_ok=True)

        if folder == None or not folder.is_dir():
            print ('usage: decode.py -d <directory_to_search> [-o <output_directory>] [-r]')
            sys.exit(2)

        all_domains = set()
        all_urls = set()
        if recursive:
            all_files = sorted(list(folder.rglob("*")))
        else:
            all_files = sorted(list(folder.glob("*")))
        for f in all_files:
            try:
                if f.is_file():
                    js = open(f)
                    content = js.read()
                    
                    num_rounds = 2
                    if len(content) > 100000: # new version. file contains library code to obfuscate
                        clean_content = ""
                        matches = re.findall(functions_regex, content, re.MULTILINE)
                        for m in matches:
                            if len(m) > len(clean_content):
                                clean_content = m

                        matches = re.findall(ext_code_regex, clean_content, re.MULTILINE)
                        code_parts = dict()
                        for m in matches:
                            code_parts[m[0]] = m[1]
                        
                        matches = re.findall(code_order.replace("NUM_REP", str(len(code_parts)-1)), clean_content.replace(" ", ""), re.MULTILINE)
                        order = list()
                        if len(matches) > 0:
                            for m in matches:
                                order = m.split("+")
                        else:
                            # New GootLoader Version 2022-05
                            code_fragments = dict()
                            result_element = ""
                            matches = re.findall(re_code_order, clean_content.replace(" ", ""), re.MULTILINE)
                            for expr in matches:
                                stmt = expr.replace(" ", "").split("=")
                                code_fragments[stmt[0]] = stmt[1].split("+")
                                result_element = code_fragments[stmt[0]]

                        
                            for element in result_element:
                                order += code_fragments[element]
                        
                        ordered_code = ""
                        for element in order:
                            ordered_code += code_parts[element]
                        content = "'" + ordered_code + "'"
                    
                    elif len(content) > 30000:
                        # New GootLoader Version 2022-10
                        num_rounds = 1

                        variables = dict()
                        functions = dict()

                        matches = re.findall(var_regex, content, re.MULTILINE)
                        for m in matches:
                            variables[m[0]] = m[1]

                        matches = re.findall(func_regex, content, re.MULTILINE)
                        for m in matches:
                            functions[m[0]] = m[1]

                        resolved_functions = dict()
                        for fx in functions:
                            resolved_functions[fx] = ""
                            var_list = functions[fx].split("+")
                            for v in var_list:
                                if v.strip() in variables:
                                    resolved_functions[fx] += variables[v.strip()]

                        real_concat = dict()
                        for k in functions:
                            matches = re.search("^.*" + str(k) + ".*;$", content, re.MULTILINE)
                            if matches.group() not in real_concat:
                                real_concat[matches.group()] = 0
                            real_concat[matches.group()] += 1
                        
                        real_con = ""
                        len_con = 0
                        for x in real_concat:
                            if real_concat[x] > len_con:
                                real_con = x
                        real_con = real_con.replace("\t", "").replace(";", "")
                        real_con = real_con.split("=")[1:][0].strip()

                        x = ""
                        for v in real_con.split("+"):
                            if v.strip() in resolved_functions:
                                x += resolved_functions[v.strip()]
                        
                        content = decode_cipher(decode(encode(x, 'latin-1', 'backslashreplace'), 'unicode-escape')) 

                    round = 0
                    while round < num_rounds:
                        matches = re.findall(code_regex, content, re.MULTILINE)
                        longest_match = ""
                        for m in matches:
                            if len(longest_match) < len(m):
                                longest_match = m

                        content = decode_cipher(decode(encode(longest_match, 'latin-1', 'backslashreplace'), 'unicode-escape')) #
                        round += 1

                    if output_folder:
                        decoded_path = output_folder / ("decoded_" + f.name)
                        w = open(decoded_path,"w")
                        w.write(content)
                        w.close()
                        print("Wrote " + str(decoded_path))
                    

                    content = content.replace("\")+(\"", "").replace("\"+\"", "")
                    for t in range(0,3):
                        domains = re.findall(breacket_regex, content.split(";")[t], re.MULTILINE)
                        if len(domains) > 0:
                            break

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
                        # New GootLoader Version 2022-04
                        content = content.replace("\")+(\"", "").replace("\")+\"", "").replace("\"+(\"", "").replace("\")+", "").replace("+(\"", "")
                        domains = re.findall(breacket_regex, content.split(";")[0], re.MULTILINE)
                        urls = re.findall(url_regex, content, re.MULTILINE)
                        if len(urls) > 0:
                            replaceables = re.findall(array_replace_regex, urls[0], re.MULTILINE)
                            if len(replaceables) > 0:
                                for d in domains:
                                    for dom in d.replace("\"", "").replace("'", "").split(","):
                                        all_domains.add(dom)
                                        all_urls.add(urls[0].replace(replaceables[0], dom) + "=")

                            print("OK - " + str(f))
                        else:
                            print("NOK - " + str(f))
                    
            except Exception as e:
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
    print ('usage: decode.py -d <directory_to_search> [-o <output_directory>] [-r]')
    sys.exit(2)
except Exception as e:
    print(e)
