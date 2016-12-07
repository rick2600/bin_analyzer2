# -*- coding: utf-8 -*-
import r2pipe
import re
import json
import pprint
import os

BINARYNAME_MAX_LENGTH = 40

class PluginChecksec:
    
    def __init__(self):
        self.desc = "analyze security mitigations"
        self.r2 = None    


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
        output = "%s | %s | %s" %(
            binary_name.ljust(BINARYNAME_MAX_LENGTH),
            str(binary["bin"]["nx"]).ljust(10),
            str(binary["bin"]["canary"]).ljust(10)
            )
        print(output)


    def print_header(self):
        header = "%s | %s | %s" %(
            "FILENAME".ljust(BINARYNAME_MAX_LENGTH),
            "NX".ljust(10),
            "CANARY".ljust(10)
            )
        print(header)
        print("="*100)        


    def get_basic_info(self, full_binary_name):
        self.r2 = r2pipe.open(full_binary_name)
        return json.loads(self.r2.cmd("ij"))
 
