#!/usr/bin/env python
# -*- coding: utf-8 -*-
# filename          : patch_wsf.py
# description       : Patch and run WSF Script
# author            : @stoerchl
# email             : patrick.schlapfer@hp.com
# date              : 20240410
# version           : 1.0
# usage             : patch_wsf.py -f <folder>
# license           : MIT
#==============================================================================

"""Raspberry Robin WSF 

IMPORTANT: This script will execute the Raspberry Robin WSF malware and must 
only be executed in a safe environment!

This module tries to patch the Raspberry Robin WSF Script. It will introduce
several WScript Echo instructions to dump the relevant variables to extract
the encoded Payload Domain and the used Cookies to download the Raspberry Robin
malware. 

Example:
            To execute the patch and run script a folder containing the
            Raspberry Robin downloaders must be supplied as an argument.

                $ python patch_wsf.py -f decoded/

As threat actors constantly change their techniques this automation might not
work on future Raspberry Robin scripts. It should however provide a starting
point for implementing future decoding automations.

"""


import re
import sys
import os
import argparse

TEMP_FILE = "temp.js"
ANALYSIS_OUTPUT = "analysis.txt"


def main(folder):
    files = os.listdir(folder)
    all_content = ""

    for fn in files:
        try:
            print("Processing file: " + fn)
            f = open(os.path.join(folder, fn))
            content = f.read()

            # first match
            find_function = r"function (\w+)\("
            res = re.findall(find_function, content)
            function_name = res[0]

            # find intermediate function
            find_intermediate = r"(\w+) = " + function_name
            res = re.findall(find_intermediate, content)
            intermediate = res[0]

            # find wscript object
            find_wscript = r"(\w+) = " + intermediate
            res = re.findall(find_wscript, content)
            wscript = res[0]

            find_calls = r", " + wscript + r"\["
            res = re.finditer(find_calls, content)

            counter = 0
            var_to_print = ""
            inject = "WScript.Echo("
            for element in res:    
                start = element.start() + (counter*len(inject))
                end = element.end() + (counter*len(inject))
                x1 = content.find(")", end)
                x2 = content.find(")", x1+1)
                section = content[end:x2]
                res = re.findall(r"[a-z]{5,}", section)
                
                if len(res) > 0:
                    inject = "WScript.Echo("
                    var_to_print = res[0]
                    inject += var_to_print+");"
                    content = content[:start+1] + inject + content[start+1:]
                    counter += 1
                
                
                if counter >= 2:
                    break
                
            with open(TEMP_FILE, "w") as outdata:
                outdata.write(content)
                
            with open(TEMP_FILE, 'r') as file:
                content = file.read()
                
            quit_instruction = r"" + intermediate + r".+\(\);"    
            content = re.sub(quit_instruction, "", content)

            with open(TEMP_FILE, "w") as outdata:
                outdata.write(content)
                
            with open(TEMP_FILE, 'r') as file:
                content = file.read()
                
            defender_instruction = r"(\w{5,}, \w{5,}, \w{5,})"
            res = re.finditer(defender_instruction, content)
            for element in res:
                end = element.end()+2
                x1 = content.rfind("[", 0, element.start())
                x2 = content.rfind(" ", 0, x1)
                section = content[x2:end]
                content = content.replace(section, "")
                
            with open(TEMP_FILE, "w") as outdata:
                outdata.write(content)
                
            stream = os.popen('cscript ' + TEMP_FILE + ' 799  runAs 0')
            output = stream.read()
            all_content += output + "\r\n"
            print(output)
        except:
            print("Error: Couldn't patch and emulate file: " + fn)
        
        
    with open(ANALYSIS_OUTPUT, "w") as outdata:
            outdata.write(all_content)


if __name__ == '__main__':
    msg = "Script to patch and emulate WSF malware to extract Payload Domain and Downlaod info"
    parser = argparse.ArgumentParser(description = msg)
    parser.add_argument("-f", "--folder", help = "Folder with WSF files", required=True)
    args = parser.parse_args()
    main(args.folder)