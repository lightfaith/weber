#!/usr/bin/env python3
"""
Global structures are defined here.
"""
from collections import OrderedDict

"""
Default configuration options
"""
config = OrderedDict()
# analysis settings
config['analysis.immediate'] = (True, bool) # should analysis be done immediately?
config['analysis.ignored_tests'] = ('', str) # list of analysis test name to NOT perform

# brute settings
config['brute.placeholder'] = ('###', str) # placeholder start and end, e.g. ###0###
config['brute.value_separator'] =   (':', str)   # separator between values
config['brute.set_separator'] =   ('\n', str)   # separator between value sets

# debug settings
config['debug.analysis'] =   (False, bool)   # stuff relevant to analysis
config['debug.command'] =    (False, bool)   # stuff relevant to user commands
config['debug.config'] =     (False, bool)   # stuff relevant to configuration
config['debug.chunks'] =     (False, bool)   # stuff relevant to Transfer-Encoding: chunked parsing
config['debug.flow'] =       (False, bool)   # stuff relevant to program flow
config['debug.mapping'] =    (False, bool)   # stuff relevant to local-remote URL mapping
config['debug.parsing'] =    (False, bool)   # stuff relevant to request/response parsing
config['debug.protocol'] =   (False, bool)   # stuff relevant to protocol decisioning
config['debug.socket'] =     (False, bool)   # stuff relevant to socket communication
config['debug.tampering'] =  (False, bool)   # stuff relevant to tampering

# edit settings
config['edit.command'] = ('vim %s', str)

# http settings
config['http.recompute_request_length'] = (True, bool) # whether request Content-Length should be recomputed before sending to server

# how things will be presented to user
config['interaction.show_upstream'] = (True, bool) # what version of RR should be presented?

# overview settings
config['overview.realtime'] =     (True, bool)  # show request/response communication on the fly
config['overview.short_request'] = (False, bool) # reduce size of too long URLs
config['overview.show_event'] =    (False, bool) # show event ID in overview
config['overview.show_size'] =     (True, bool)  # show response size in overview
config['overview.show_time'] =     (False, bool) # show forwarded time in overview # TODO also relative?
config['overview.show_uri'] =      (True, bool)  # show uri in overview

# proxy-relevant settings
config['proxy.host'] =     ('localhost', str)
config['proxy.port'] =     (8555, int)
config['proxy.sslport'] =  (8556, int)
config['proxy.sslcert'] =  ('cert.pem', str)
config['proxy.sslkey'] =   ('key.pem', str)
config['proxy.threaded'] = (True, bool)
config['proxy.default_protocol'] = ('http', str) 

# spoof
config['spoof.arguments'] = (False, bool) # should arguments be taken into consideration for spoofing?

# tamper
config['tamper.requests'] =  (False, bool) # should all requests be tampered by default?
config['tamper.responses'] = (False, bool) # should all responses be tampered by default?


"""
Dictionary of all supported protocols (filled in source/<protocol>.py)
"""
protocols = {}


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
Template database (initialized in structures.py)
"""
tdb = None

"""
Events (filled on request in commands.py)
"""
events = {}
"""
Local-remote URI mapping (initialized in structures.py)
"""
mapping = None 

"""
Spoof dictionaries (URI in str format  ->  path to file)
                   (old string -> new string)
"""
spoof_files = {}
spoof_regexs = {}

"""
(path, list of lists (values for bruteforcing))
"""
brute = None

"""
List of local URIs that could not be forwarded
"""
forward_fail_uris = []

"""
Dictionary of analysis modules, filled in source/analysis/*
{
    'name': {'enabled': True, 'rr_tests': [], }
}
"""
analysis = {}

"""
List of Server() objects holding info about RRs, cookies etc.
"""
servers = []

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


