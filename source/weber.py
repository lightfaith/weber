#!/usr/bin/env python3
"""
Global structures are defined here.
"""


"""
Default configuration options
"""
config = {
	# proxy-relevant settings
	'proxy.host': 'localhost',
	'proxy.port': 8555,
        'proxy.threaded': True,

        # debug settings
        'debug.command': False, # stuff relevant to user commands
        'debug.config':  True,  # stuff relevant to configuration
        'debug.mapping': True,  # stuff relevant to local-remote URL mapping
        'debug.parsing': True,  # stuff relevant to request/response parsing
        'debug.socket':  False, # stuff relevant to socket communication
}

"""
Dictionary of all available commands (filled in source/commands.py)
"""
commands = {}

"""
Proxy object (initialized in weber)
"""
proxy = None

"""
Request-response database (initialized in structures.py)
"""
rrdb = None

"""
Local-remote URI mapping (initialized in structures.py)
"""
mappings = None 
