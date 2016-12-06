# -*- coding: utf-8 -*-

import r2pipe
import re
import json
import pprint
import os

class PluginInfo:
    
    def __init__(self):
        self.desc = "show basic informations about the binaries"

    def run(self, binaries):
        self.print_header()

        for full_binary_name in binaries:
            binary = self.get_json(full_binary_name)
            binary_name = os.path.basename(full_binary_name)

            if self.isvalid(binary["core"]["format"]):
                output = "%s | %s | %s | %s" %(
                    binary_name.ljust(20),
                    binary["bin"]["class"].ljust(10),
                    binary["bin"]["os"].ljust(10),
                    binary["core"]["type"].ljust(10)
                    )
                print(output)
            else:
                pass
                #print(binary["core"]["format"]))


    def isvalid(self, binary_type):
        return binary_type in ["pe", "elf", "elf64"]


    def print_header(self):
        header = "%s | %s | %s | %s" %(
            "FILENAME".ljust(20),
            "CLASS".ljust(10),
            "OS".ljust(10),
            "TYPE".ljust(10)
            )
        print(header)
        print("="*100)


    def get_json(self, full_binary_name):
        r2 = r2pipe.open(full_binary_name)
        return json.loads(r2.cmd("ij"))

"""
{u'bin': {u'arch': u'x86',
          u'binsz': u'531368',
          u'bintype': u'pe',
          u'bits': 32,
          u'canary': False,
          u'class': u'PE32',
          u'cmp.csum': u'0x00089c07',
          u'compiled': u'Mon Feb 29 20:04:07 2016',
          u'crypto': False,
          u'dbg_file': u'',
          u'endian': u'little',
          u'guid': u'',
          u'havecode': True,
          u'hdr.csum': u'0x00089c07',
          u'intrp': u'',
          u'lang': u'',
          u'linenum': True,
          u'lsyms': True,
          u'machine': u'i386',
          u'maxopsz': 16,
          u'minopsz': 1,
          u'nx': False,
          u'os': u'windows',
          u'pcalign': 0,
          u'pic': False,
          u'relocs': True,
          u'rpath': u'',
          u'static': False,
          u'stripped': True,
          u'subsys': u'Windows GUI',
          u'va': True},
 u'core': {u'block': 256,
           u'fd': 7,
           u'file': u'/home/rick/Codes/python/bin_analyzer2/samples/putty.exe',
           u'format': u'pe',
           u'iorw': False,
           u'mode': u'-r--',
           u'obsz': 0,
           u'size': 531368,
           u'type': u'EXEC (Executable file)'}}
{u'bin': {u'arch': u'x86',
          u'binsz': u'33722',
          u'bintype': u'elf',
          u'bits': 64,
          u'canary': True,
          u'class': u'ELF64',
          u'compiled': u'',
          u'crypto': False,
          u'dbg_file': u'',
          u'endian': u'little',
          u'guid': u'',
          u'havecode': True,
          u'intrp': u'/lib64/ld-linux-x86-64.so.2',
          u'lang': u'c',
          u'linenum': False,
          u'lsyms': False,
          u'machine': u'AMD x86-64 architecture',
          u'maxopsz': 16,
          u'minopsz': 1,
          u'nx': True,
          u'os': u'linux',
          u'pcalign': 0,
          u'pic': False,
          u'relocs': False,
          u'rpath': u'NONE',
          u'static': False,
          u'stripped': True,
          u'subsys': u'linux',
          u'va': True},
 u'core': {u'block': 256,
           u'fd': 7,
           u'file': u'/home/rick/Codes/python/bin_analyzer2/samples/id',
           u'format': u'elf64',
           u'iorw': False,
           u'mode': u'-r--',
           u'obsz': 0,
           u'size': 35520,
           u'type': u'EXEC (Executable file)'}}
"""
