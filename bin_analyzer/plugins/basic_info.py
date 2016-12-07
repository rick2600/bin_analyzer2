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
            binary = self.get_basic_info(full_binary_name)
            if self.isvalid(binary):
                self.analyze(binary)


    def isvalid(self, binary):
        return binary["core"]["format"] in ["pe", "elf", "elf64"]


    def analyze(self, binary):
        binary_name = os.path.basename(binary['core']['file'])
        output = "%s | %s | %s | %s" %(
            binary_name.ljust(20),
            binary["bin"]["class"].ljust(10),
            binary["bin"]["os"].ljust(10),
            binary["core"]["type"].ljust(10)
            )
        print(output)


    def print_header(self):
        header = "%s | %s | %s | %s" %(
            "FILENAME".ljust(20),
            "CLASS".ljust(10),
            "OS".ljust(10),
            "TYPE".ljust(10)
            )
        print(header)
        print("="*100)


    def get_basic_info(self, full_binary_name):
        r2 = r2pipe.open(full_binary_name)
        return json.loads(r2.cmd("ij"))
