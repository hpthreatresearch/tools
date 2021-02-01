#!/usr/bin/env python
# -*- coding: utf-8 -*-
# filename          : decode.py
# description       : Extracts URLs from Dridex loader Excel documents
# author            : @stoerchl
# email             : patrick.schlapfer@hp.com
# date              : 20210201
# version           : 1.2
# usage             : python decode.py -d <directory_to_search>
# license           : MIT
# py version        : 3.9.1
#==============================================================================

"""Dridex Excel loader URL extractor.

This module tries to extract embedded URLs from Dridex Excel loader documents.
It is able to decode URLs using six types of encoding algorithms. For each document
the six encoding algorithms are executed and based on the result the correct one
delivers the decoded URLs. The decoded URLs are directly written to a file named
`urls.txt`. If the decoding for a specific file fails, an error indication is
printed on the console.

Example:
            To execute the decoding script a folder containing the
            Dridex loader Excel documents must be supplied
            as an argument.

                $ python decode.py -d samples/20201208/

Based on openpyxl at the moment only `.xlsm` documents are supported.
As threat actors constantly change their techniques this automation might not
work on future Dridex loader documents. It should however provide a starting 
point for implementing future decoding automations.

Todo:
            * Add .xls decoding capabilities
            * Adapt to future Dridex loader encoding algorithms

"""

import re
import getopt
import sys
import openpyxl
from pathlib import Path

all_args = sys.argv[1:]

def write_to_file(file_name, value):
    try:
        if "=" in str(value):
            value = value.split("=")[0]
        if "!" in str(value):
            value = value.split("!")[0]
        f = open(file_name, "a")
        f.write(value + "\n")
        f.close()
    except Exception as e:
        print(e)

def reverse_encoding(reverse_encoding_dict, cell):
    try:
        int_value = int(cell.value)
        reverse_encoding_dict[int_value] = chr(cell.row)
    except Exception as e:
        pass
    return reverse_encoding_dict

def get_reverse_encoding(reverse_encoding_dict):
    try:
        full = ""
        for x in sorted(reverse_encoding_dict):
            full += reverse_encoding_dict[x]
        urls = full.split("!")[0].split("$")
        found_urls = False
        for url in urls:
            if url.startswith("http"):
                found_urls = True
                write_to_file("urls.txt", str(url))
        return found_urls
    except:
        return False

def char_offset_encoding(char_offset_output, val):
    try:
        for num in range(3):
            potential_url = ""
            for x in val:
                potential_url += chr(int(ord(x)+num))
            if "http" in potential_url:
                char_offset_output += potential_url[potential_url.find("http"):] + "?"
    except:
        pass
    return char_offset_output

def char_minus_encoding(char_minus_output, val):
    try:
        char_minus_output += chr(int(val-1))
    except:
        pass
    return char_minus_output

def scramle_encoding(scramle_encoding_output, val, offset):
    try:
        for i in range(0, len(val)):
            if (i - 1) % 2 == 1:
                scramle_encoding_output += chr(ord(val[i:i+1])-offset)
            else:
                scramle_encoding_output += chr(ord(val[i:i+1])+offset)
        scramle_encoding_output += "!"
    except:
        pass
    return scramle_encoding_output

def substring_concat_encoding(substring_concat_encoding_output, val):
    try:
        if len(val) > 2:
            substring_concat_encoding_output += val[1:2]
    except:
        pass
    return substring_concat_encoding_output

def format_encoding(format_encoding_output, cell):
    try:
        if not cell.number_format == "General":
            format_encoding_output += chr(cell.column)
    except:
        pass
    return format_encoding_output

def hex_encoding(hex_encoding_output, val):
    try:
        hex_encoding_output += chr(int(str(val), 16))
    except:
        pass
    return hex_encoding_output

# Regex Source: https://stackoverflow.com/questions/839994/extracting-a-url-in-python
def extract_decoded_urls(content):
    try:
        content = content.replace("_", "$")
        found_urls = False
        urls = re.findall(r"""((?:https?://)(?:(?:www\.)?(?:[\da-z\.-]+)\.(?:[a-z]{2,6})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?(?:/[0-9a-z\._-]*)*/?)""",content)
        for url in urls:
            found_urls = True
            write_to_file("urls.txt", str(url))
    except:
        return False
    return found_urls

try:
    opts, arg = getopt.getopt(all_args, 'd:')
    if len(opts) != 1:
        print ('usage: decode.py -d <directory_to_search>')
    else:
        opt, arg_val = opts[0]
        all_files = sorted(list(Path(arg_val).rglob("*.xlsm")))
        for f in all_files:

            workbook = openpyxl.load_workbook(str(f), read_only=True)
            found_urls = False
            worksheet_data = list()
            for worksheet in workbook.worksheets:
                try:
                    rows = worksheet.rows
                    
                    reverse_encoding_dict = dict()
                    char_offset_output = ""
                    char_minus_output = ""
                    scramle_encoding_output = ""
                    substring_concat_encoding_output = ""
                    format_encoding_output = ""
                    hex_encoding_output = ""
                    
                    worksheet_content = ""
                    for row in rows:
                        for cell in row:
                            format_encoding_output = format_encoding(format_encoding_output, cell)
                            if cell.value:
                                cell_value = cell.value
                                worksheet_content += cell_value
                                char_minus_output = char_minus_encoding(char_minus_output, cell_value)
                                reverse_encoding_dict = reverse_encoding(reverse_encoding_dict, cell)
                                scramle_encoding_output = scramle_encoding(scramle_encoding_output, cell_value, 1)
                                scramle_encoding_output = scramle_encoding(scramle_encoding_output, cell_value, 2)
                                scramle_encoding_output = scramle_encoding(scramle_encoding_output, cell_value, 3)
                                substring_concat_encoding_output = substring_concat_encoding(substring_concat_encoding_output, cell_value)
                                hex_encoding_output = hex_encoding(hex_encoding_output, cell_value)
                                char_offset_output = char_offset_encoding(char_offset_output, cell_value)
                                
                    worksheet_data.append(worksheet_content)
                    found_urls += get_reverse_encoding(reverse_encoding_dict)

                    total_output = char_minus_output + "$" + \
                        scramle_encoding_output + "$" + \
                        substring_concat_encoding_output + "$" + \
                        format_encoding_output + "$" + \
                        hex_encoding_output + "$" + \
                        char_offset_output
                    found_urls += extract_decoded_urls(total_output)

                except Exception as ex:
                    pass # don't worry, be happy.

            url_output = ""
            try:
                for char_off in range(0, len(worksheet_data[len(worksheet_data)-1])):
                    for ws in range(len(worksheet_data)-1, 0, -1):
                        url_output += worksheet_data[ws][char_off]
                found_urls += extract_decoded_urls(url_output)
            except:
                pass # no multi-worksheet encoding used.
            
            if found_urls:
                print("ok - " + str(f))
            else:
                print("error - " + str(f))

except getopt.GetoptError:
    print ('usage: decode.py -d <directory_to_search>')
    sys.exit(2)
