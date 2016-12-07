# -*- coding: utf-8 -*-
import r2pipe
import re
import json
import pprint
import os
import sets

BINARYNAME_MAX_LENGTH = 40

class PluginTagger:
    
    def __init__(self):
        self.desc = "show imports"
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
        import_tags = self.tag_binary_using_imports(binary)
        tags = import_tags
        output = "%s | %s" %(
            binary_name.ljust(40),
            ', '.join(tags)
            )
        print(output)        
          

    def tag_binary_using_imports(self, binary):
        if binary["core"]["format"] in ["elf", "elf64"]:
            return self.tag_binary_using_imports_ELF()
        elif binary["core"]["format"] in ["pe"]:
            return self.tag_binary_using_imports_PE()

    def tag_binary_using_imports_ELF(self):
        exec_funcs = ["system", "popen","execl", "execlp", "execle","execv","execvp","execvp", "execve"]
        rand_funcs = ["srand", "rand"]
        heap_funcs = ["malloc", "calloc", "realloc"]
        net_funcs = ["socket", "getaddrinfo", "recv", "recvmsg", "recvfrom", "gethostbyname"]        
        net_server_funcs = ["accept", "listen"]
        net_client_funcs = ["connect"]
        thread_funcs = ["pthread_create"]

        tags = sets.Set()
        for imp in json.loads(self.r2.cmd("iij")):
            if imp['type'] == 'FUNC' and imp['name'] in exec_funcs:
                exec_funcs.remove(imp['name'])
                tags.add('exec')
            if imp['type'] == 'FUNC' and imp['name'] in rand_funcs:
                rand_funcs.remove(imp['name'])
                tags.add('rand')
            if imp['type'] == 'FUNC' and imp['name'] in heap_funcs:
                heap_funcs.remove(imp['name'])
                tags.add('heap')
            if imp['type'] == 'FUNC' and imp['name'] in net_server_funcs:
                net_server_funcs.remove(imp['name'])
                tags.add('net server')
            if imp['type'] == 'FUNC' and imp['name'] in net_funcs:
                net_funcs.remove(imp['name'])
                tags.add('net')
            if imp['type'] == 'FUNC' and imp['name'] in net_client_funcs:
                net_client_funcs.remove(imp['name'])
                tags.add('net client')
            if imp['type'] == 'FUNC' and imp['name'] in thread_funcs:
                thread_funcs.remove(imp['name'])
                tags.add('thread')

        return list(tags)

    def tag_binary_using_imports_PE(self):
        for imp in json.loads(self.r2.cmd("iij")):
            print imp        
        return []        


    def print_header(self):
        header = "%s | %s " %(
            "FILENAME".ljust(BINARYNAME_MAX_LENGTH),
            "TAGS".ljust(10)
            )
        print(header)
        print("="*100)


    def get_basic_info(self, full_binary_name):
        self.r2 = r2pipe.open(full_binary_name)
        return json.loads(self.r2.cmd("ij"))
