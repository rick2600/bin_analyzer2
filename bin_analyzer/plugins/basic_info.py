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
