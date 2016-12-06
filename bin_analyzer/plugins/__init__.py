# -*- coding: utf-8 -*-

import pkgutil
import inspect

plugins_list = {}

for loader, plugin_name, is_pkg in pkgutil.walk_packages(__path__):
    plugin = loader.find_module(plugin_name).load_module(plugin_name)

    for name, value in inspect.getmembers(plugin):
        if name.startswith('__'):
            continue

        if name.startswith('Plugin'):
            plugins_list[plugin_name] = value

