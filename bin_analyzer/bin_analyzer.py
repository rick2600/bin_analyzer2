# -*- coding: utf-8 -*-
from __future__ import print_function   
import os
import sys
#from plugins.plugin_info import Plugin_Info
import plugins


class BinAnalyzer:

    def __init__(self, args):
        self.args = args
        self.plugins_to_run = plugins.plugins_list.keys()
        print(self.args)
        
        if args.list:
            self.list_plugins()
            sys.exit(0)
        else:
            self.select_plugins_to_run()
            self.binaries = self.get_binaries_list()
    

    def select_plugins_to_run(self):
        if self.args.plugins == None:
            self.plugins_to_run = plugins.plugins_list.keys()
        else:
            self.plugins_to_run = self.args.plugins.split(',')

        
    def get_binaries_list(self):
        binaries = []
        if os.path.isfile(self.args.file):
            binary_path = os.path.abspath(os.path.join(self.args.file))
            binaries.append(binary_path)
        elif os.path.isdir(self.args.file):
            for (folder, _, files) in os.walk(self.args.file):
                for f in files:
                    binary_path = os.path.abspath(os.path.join(folder, f))
                    binaries.append(binary_path)
        return binaries

    def scan(self):
        for plugin_to_run in self.plugins_to_run:
            if plugin_to_run in plugins.plugins_list.keys():
                print("Running plugin '%s'" %(plugin_to_run))
                plugin = plugins.plugins_list[plugin_to_run]()
                plugin.run(self.binaries)
                print("")
            else:
                print ("Plugin '%s' not available!" %(plugin_to_run))
    
    def list_plugins(self):
        for plugin_name in plugins.plugins_list.keys():
            plugin = plugins.plugins_list[plugin_name]()
            output = "%s | %s" %(plugin_name.ljust(20), plugin.desc)
            print(output)
