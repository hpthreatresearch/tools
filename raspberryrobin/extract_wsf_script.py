#!/usr/bin/env python
# -*- coding: utf-8 -*-
# filename          : extract_wsf_script.py
# description       : Extract WSF Script from Raspberry Robin Downloader
# author            : @stoerchl
# email             : patrick.schlapfer@hp.com
# date              : 20240410
# version           : 1.0
# usage             : extract_wsf_script.py -i <input_folder> -o <output_folder>
# license           : MIT
#==============================================================================

"""Raspberry Robin WSF Extractor

This module tries to extract the WSF Script from the Raspberry Robin downloader.

Example:
            To execute the extraction script a folder containing the
            Raspberry Robin downloaders must be supplied as an argument.

                $ python extract_wsf_script.py -i samples/20240410/ -o decoded/

As threat actors constantly change their techniques this automation might not
work on future Raspberry Robin scripts. It should however provide a starting
point for implementing future decoding automations.

"""


import jsbeautifier
import os
import sys
import argparse

def main(input_folder, output_folder):
    files = os.listdir(input_folder)

    for f in files:
        with open(os.path.join(input_folder, f), "rb") as indata:
            data = indata.read()
        
        start = 0
        script = ""
        while start != -1 and len(script) < 2000:
            text = data.decode("utf-8", errors="ignore")
            start = text.find("var", start+1)
            end = text.find("\n", start)
            script = text[start:end]
        
        res = jsbeautifier.beautify(script)
        with open(os.path.join(output_folder, f), "w", encoding='ascii') as outdata:
            outdata.write(res)
            
        print("Processed: " + f)


if __name__ == '__main__':
    msg = "Script to extract WSF script code from binary-mixed file"
    parser = argparse.ArgumentParser(description = msg)
    parser.add_argument("-i", "--input_folder", help = "Folder with WSF files", required=True)
    parser.add_argument("-o", "--output_folder", help = "Folder with WSF files", required=True)
    args = parser.parse_args()
    main(args.input_folder, args.output_folder)