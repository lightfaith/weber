#!/usr/bin/env python3
"""
Global structures are defined here.
"""
from collections import OrderedDict

"""
Default configuration options
"""
config = OrderedDict()
# debug settings
config['debug.command'] = False   # stuff relevant to user commands
config['debug.config'] =  False   # stuff relevant to configuration
config['debug.chunks'] =  False   # stuff relevant to Transfer-Encoding: chunked parsing
config['debug.mapping'] = True   # stuff relevant to local-remote URL mapping
config['debug.parsing'] = False   # stuff relevant to request/response parsing
config['debug.socket'] =  False   # stuff relevant to socket communication

# overview settings
config['overview.realtime'] = True  # show request/response communication on the fly
config['overview.size'] = True  # show response size in overview
config['overview.time'] = True  # show delay in overview

# proxy-relevant settings
config['proxy.host'] = 'localhost'
config['proxy.port'] = 8555
config['proxy.sslport'] = 8556
config['proxy.threaded'] = True

# tamper
config['tamper.default'] = False # should all requests be tampered by default?

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
    'Weber tip of the day: Use \'pr\' to print overview of all received requests.',
]


