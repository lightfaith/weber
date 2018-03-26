#!/usr/bin/env python3
"""
Protocol loader
"""
import os, importlib
from source import log
from source import weber

debug_lines = ['Loaded known analysis modules...']

for f in os.listdir(os.path.dirname(os.path.abspath(__file__))):
    if f.endswith('.py') and f not in ('analysis.py', '__init__.py'):
        name = f.rpartition('.')[0]
        debug_lines.append('      %s' % name)
        importlib.import_module('source.analysis.' + name)


log.debug_analysis('\n'.join(debug_lines))
