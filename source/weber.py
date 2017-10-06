#!/usr/bin/env python3
"""
Global structures are defined here.
"""
from collections import OrderedDict

"""
Default configuration options
"""
config = {
        # debug settings
        'debug.command': False,  # stuff relevant to user commands
        'debug.config':  False,   # stuff relevant to configuration
        'debug.mapping': False,   # stuff relevant to local-remote URL mapping
        'debug.parsing': True,   # stuff relevant to request/response parsing
        'debug.socket':  False,   # stuff relevant to socket communication

	# proxy-relevant settings
	'proxy.host': 'localhost',
	'proxy.port': 8555,
	'proxy.sslport': 8556,
        'proxy.threaded': True,
        
        # realtime
        'realtime.show': True,  # show request/response communication on the fly

        # tamper
        'tamper.default': False, # should all requests be tampered by default?
}

"""
Dictionary of all available commands (filled in source/commands.py)
"""
commands = OrderedDict()

"""
Proxy object (initialized in weber)
"""
proxy = None

"""
Request-response database (initialized in structures.py)
"""
rrdb = None

"""
Events (filled on request in commands.py)
"""
events = {}
"""
Local-remote URI mapping (initialized in structures.py)
"""
mappings = None 


"""
MOTDs
"""
motd = [
    'GO!',
    'Go go go!',
    'SHALL WE PLAY A GAME?',
    'GREETINGS PROFESSOR FALKEN',
    'ACCESS GRANTED',
    'W-W-W-Weber! How can I help you?',
    'Change your passwords.',
    'Hold the door!',
    'Hodor.',
    'Bend the knee!',
    'Bow before me, for I am root.',
    'Na na na na na na na na.',

    'HTTP/1.1 200 OK',
    'HTTP/1.1 403 Forbidden',
    'HTTP/1.1 404 Not Found',

    'Weber tip of the day: Use \'q\' to quit the program.',
    'Weber tip of the day: Use \'pr\' to print all received requests.',
]


