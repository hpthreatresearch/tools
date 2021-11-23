#!/usr/bin/env python
# -*- coding: utf-8 -*-
# filename          : decode.py
# description       : Extracts URLs and payloads from RatDispenser JavaScript
# author            : @stoerchl
# email             : patrick.schlapfer@hp.com
# date              : 20211101
# version           : 1.0
# usage             : python decode.py -d <directory_to_search>
# license           : MIT
# py version        : 3.9.1
#==============================================================================

"""RatDispenser decoder and URL extractor

This module tries to deobfuscate RatDispenser JavaScript and extract its next stage
URLs. In case the JavaScript is not a loader but a dropper, the extractor tries to 
save the embedded payload into the folder drops/. RatDispenser is a 
JavaScript downloader or dropper respectively, which is known to deploy various RAT's
such as WSHRAT, STRRAT, RemcosRAT and Formbook. 

Example:
            To execute the decoding script a folder containing the
            RatLoader script must be supplied as an argument.

                $ python decode.py -d samples/20211101/

As threat actors constantly change their techniques this automation might not
work on future RatDispenser scripts. It should however provide a starting
point for implementing future decoding automations.

"""

import re
import getopt
import base64
import sys
import os
import warnings
import magic
from codecs import encode, decode
from pathlib import Path
from hashlib import sha256

warnings.filterwarnings("ignore", category=DeprecationWarning)

code_regex1 = r"(?<!\\)(?:\\\\)*'([^'\\]*(?:\\.[^'\\]*)*)'"
code_regex2 = r"(?<!\\)(?:\\\\)*\"([^\"\\]*(?:\\.[^\"\\]*)*)\""
regex_list = [code_regex1, code_regex2]
url_regex = "(?i)(?:https?:\/\/[^='\"]+)"
byte_regex = r"(?i)\[Byte\]\(?(0x[\dA-Fa-f]+)"
add_regex = r"\d+\+\d+"
char_regex = r"(?i)\[Char\]\(?([\dA-Fa-f]+)\)?"
regexp_regex = r"RegExp\(*\"([^\"\\]*(?:\\.[^\"\\]*)*)\""
replace_regex = r"\.replace\(\w+, *\"([^\"\\]*(?:\\.[^\"\\]*)*)\""

all_args = sys.argv[1:]

def byte_replace(match):
    match = match.group(1)
    return str(int(match, 16))

def ascii_replace(match):
    match = match.group(1)
    return "\"" + chr(int(match)) + "\""

def addition_replace(match):
    match = match.group()
    add = match.split("+")
    return str(int(add[0]) + int(add[1]))
    
def handle_dropper(message, to_replace="", replacement=""):
    longest_match = ""
    malware_family = "Unknown"
    for regex in regex_list:
        matches = re.findall(regex, message, re.MULTILINE)
        for m in matches:
            if len(longest_match) < len(m):
                longest_match = m
    
    if not longest_match:
        longest_match = message
        
    matches = re.findall(regexp_regex, message, re.MULTILINE)
    
    if not to_replace:
        if matches:
            to_replace = matches[0]
    
    if not replacement:
        matches = re.findall(replace_regex, message, re.MULTILINE)
        if matches:
            replacement = matches[0]
    
    if to_replace and replacement:
        longest_match = longest_match.replace(to_replace, replacement)
    
    base64_bytes = longest_match.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    file_type = magic.from_buffer(message_bytes).lower()
    
    if "zip archive" in file_type:
        malware_family = "STRRAT"
    elif "pe" in file_type and "executable" in file_type:
        if "Remcos" in message_bytes.decode("utf-8", "ignore"):
            malware_family = "RemcosRAT"
    elif "java archive" in file_type:
        strings = message_bytes.decode("utf-8", "ignore")
        if "adwind" in strings or "jrat" in strings.lower():
            malware_family = "AdWind"
        elif "sogomn" in strings and "Ratty" in strings:
            malware_family = "Ratty"
        
    h = sha256()
    h.update(message_bytes)
    sha256_hash = h.hexdigest()
    all_drops.add(sha256_hash)
    
    if not os.path.exists("drops"):
        os.makedirs("drops")
        
    wf = open('drops/' + sha256_hash, 'wb')
    wf.write(message_bytes)
    wf.close()
    
    return malware_family

try:
    opts, arg = getopt.getopt(all_args, 'd:')
    if len(opts) != 1:
        print ('usage: decode.py -d <directory_to_search>')
    else:
        opt, arg_val = opts[0]
        all_urls = set()
        all_drops = set()
        all_files = sorted(list(Path(arg_val).rglob("*")))
        for f in all_files:
            malware_family = "Unknown"
            try:
                js = open(f)
                content = js.read().replace("\\\"", "'").replace("\\'", "\"")
                use_regex = None
                
                for regex in regex_list:
                    use_regex = regex
                    matches = re.findall(use_regex, content, re.MULTILINE)
                    longest_match = ""
                    for m in matches:
                        if len(longest_match) < len(m):
                            longest_match = m
                    
                    position = content.find(longest_match)
                    try:
                        var_name = content[position-50:position].split("=")[-2].split(".")[-1].strip().split(" ")[-1]
                    except:
                        var_name = ""
                    
                    init_pos = content.find(var_name)
                    var_position = content.rfind(var_name)
                    
                    if init_pos != var_position and re.match("\w+", var_name):
                        break
                    
                for regex in regex_list:
                    var_content = content[var_position:var_position+50].split("\n")[0]
                    matches = re.findall(regex, var_content, re.MULTILINE)
                    if len(matches) > 0:
                        break
                
                if len(matches) == 0:
                    var_content = content[position+len(longest_match)+2:position+len(longest_match)+50].split(")")[0].replace("\n", "")
                    for regex in regex_list:
                        matches = re.findall(regex, var_content, re.MULTILINE)
                        if len(matches) > 0:
                            break
                        
                counter = 0
                for m in matches:
                    longest_match = longest_match.replace("{"+str(counter)+"}", m)
                    counter += 1
                
                base64_bytes = longest_match.encode('ascii')
                message_bytes = base64.b64decode(base64_bytes)
                message = message_bytes.decode('ascii') # this is the second stage loader
                
                detection = re.findall(r"\\x", message, re.MULTILINE)
                
                found_urls = False
                if len(detection) > 100:
                    for regex in regex_list:
                        matches = re.findall(regex, message, re.MULTILINE)
                        decoded_list = list()
                        longest_index = 0
                        max_length = 0
                        counter = 0
                        
                        for m in matches:
                            try:
                                decoded = bytes.fromhex(m.replace("\\x", "")).decode("ascii")
                            except:
                                decoded = m
                                
                            if len(decoded) > max_length:
                                max_length = len(decoded)
                                longest_index = counter
                            
                            decoded_list.append(decoded)
                            counter += 1
                            
                            if len(message) < 50000:
                                urls = re.findall(url_regex, decoded, re.MULTILINE)
                                
                                if urls: # Bash downloader
                                    for u in urls:
                                        found_urls = True
                                        malware_family = "Formbook"
                                        all_urls.add(u)
                                        
                                else: # Powershell downloader
                                    for e in decoded.split(" "):
                                        try:
                                            base64_bytes = e.encode('ascii')
                                            message_bytes = base64.b64decode(base64_bytes)
                                            ascii_message = message_bytes.decode('ascii').replace("\x00", "").replace("'", "\"").replace(" ", "")
                                            if ascii_message:
                                                ascii_message = re.sub(byte_regex, byte_replace, ascii_message)
                                                ascii_message = re.sub(add_regex, addition_replace, ascii_message)
                                                ascii_message = re.sub(char_regex, ascii_replace, ascii_message)
                                                ascii_message = ascii_message.replace("\"+\"", "")
                                                urls = re.findall(url_regex, ascii_message, re.MULTILINE)
                                                if urls:
                                                    malware_family = "Panda Stealer"
                                                    for u in urls:
                                                        found_urls = True
                                                        all_urls.add(u)
                                        except:
                                            pass # not base64.
                                        
                        if len(message) >= 50000 and len(decoded_list) > 2:
                            if "WSHRAT" in decoded_list:
                                malware_family = "WSHRAT"
                                h = sha256()
                                h.update(message.encode('ascii'))
                                sha256_hash = h.hexdigest()
                                all_drops.add(sha256_hash)
                                
                                if not os.path.exists("drops"):
                                    os.makedirs("drops")
                                    
                                wf = open('drops/' + sha256_hash, 'w')
                                wf.write(message)
                                wf.close()
                            else:
                                malware_family = handle_dropper(decoded_list[longest_index], decoded_list[longest_index+1], decoded_list[longest_index+3])
                                    
                else: # Dropper
                    malware_family = handle_dropper(message)
                    
                print("OK - " + str(f) + " : " + ("RatDispenser (Loader)" if found_urls else "RatDispenser (Dropper)") + " -> " + malware_family)
            except Exception as e:
                print("ERROR - Could not decode RatLoader - " + str(f))

        print("\nFound URLs: (" + str(len(all_urls)) + ")")
        w = open("urls.txt", "a")
        for url in all_urls:
            w.write(url + "\n")
        w.close()
        print("> Wrote file: urls.txt")
        
        print("\nFound Payloads: (" + str(len(all_drops)) + ")")
        if all_drops:
            print("> Saved payloads in drops/")

except getopt.GetoptError:
    print ('usage: decode.py -d <directory_to_search>')
    sys.exit(2)
