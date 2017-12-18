#!/usr/bin/env python3
"""
Global structures are defined here.
"""
from collections import OrderedDict

"""
Default configuration options
"""
config = OrderedDict()
# brute settings
config['brute.placeholder'] = ('###', str) # placeholder start and end, e.g. ###0###
config['brute.valueseparator'] =   (':', str)   # separator between values
config['brute.setseparator'] =   ('\n', str)   # separator between value sets

# debug settings
config['debug.command'] =    (False, bool)   # stuff relevant to user commands
config['debug.config'] =     (False, bool)   # stuff relevant to configuration
config['debug.chunks'] =     (False, bool)   # stuff relevant to Transfer-Encoding: chunked parsing
config['debug.mapping'] =    (False, bool)   # stuff relevant to local-remote URL mapping
config['debug.parsing'] =    (False, bool)   # stuff relevant to request/response parsing
config['debug.socket'] =     (False, bool)   # stuff relevant to socket communication
config['debug.tampering'] =  (True, bool)   # stuff relevant to tampering

# edit settings
config['edit.command'] = ('vim %s', str)

# overview settings
config['overview.realtime'] = (True, bool)  # show request/response communication on the fly
config['overview.size'] =     (True, bool)  # show response size in overview # TODO
config['overview.time'] =     (True, bool)  # show delay in overview # TODO

# proxy-relevant settings
config['proxy.host'] =     ('localhost', str)
config['proxy.port'] =     (8555, int)
config['proxy.sslport'] =  (8556, int)
config['proxy.sslcert'] =  ('cert.pem', str)
config['proxy.sslkey'] =   ('key.pem', str)
config['proxy.threaded'] = (True, bool)

# spoof
config['spoof.arguments'] = (False, bool) # should arguments be taken into consideration for spoofing

# tamper
config['tamper.requests'] =     (False, bool) # should all requests be tampered by default?
config['tamper.responses'] =    (False, bool) # should all responses be tampered by default?
config['tamper.showupstream'] = (True, bool) # what version of RR should be presented?


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
Spoof dictionary (URI in str format  ->  path to file)
"""
spoofs = {}

"""
(path, list of lists (values for bruteforcing))
"""
brute = None


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


