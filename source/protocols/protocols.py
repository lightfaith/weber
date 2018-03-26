#!/usr/bin/env python3
"""
Protocol loader
"""
import os, importlib
from source import weber
from source.lib import *
from source import log


debug_lines = ['Loaded known protocols...']

for f in os.listdir(os.path.dirname(os.path.abspath(__file__))):
    if f.endswith('.py') and f not in ('protocols.py', '__init__.py'):
        name = f.rpartition('.')[0]
        debug_lines.append('      %s' % name)
        importlib.import_module('source.protocols.' + name)

log.debug_protocol('\n'.join(debug_lines))
