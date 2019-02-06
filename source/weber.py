#!/usr/bin/env python3
"""
Global structures are defined here.
"""
from source import log
from collections import OrderedDict
from source.lib import positive
"""
Default configuration options
"""
config = OrderedDict()

class Option():
    """

    """
    def __init__(self, default_value, data_type, immutable=False):
        self.__data_type = data_type
        self.value = default_value
        self.immutable = immutable

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, v):
        if self.__data_type is bool:
            self.__value = positive(v)
        else:
            try:
                self.__value = self.__data_type(v)
            except:
                log.err('Option error - cannot cast \'%s\' to %s' % 
                        (v, self.__data_type))
    
    def get_text_value(self):
        """
        Returns value suitable for printing.
        """
        result = (str(self.value) if self.__data_type != str 
                                 else '\'%s\'' % self.value)
        for old, new in [
                ('\n', '\\n'),
                ('\r', '\\r'),
            ]:
            result = result.replace(old, new)
        return result

# analysis settings
config['analysis.immediate'] = Option(True, bool) # should analysis be done immediately?
config['analysis.ignored_tests'] = Option('', str) # list of analysis test name to NOT perform; space-separated

# brute settings
config['brute.placeholder'] = Option('###', str) # placeholder start and end, e.g. ###0###
config['brute.value_separator'] =   Option(';', str)   # separator between values
config['brute.rps'] =   Option(20, int)   # maximum requests per second
config['brute.set_separator'] =   Option('\n', str)   # separator between value sets

# crawl settings
config['crawl.save_path'] = Option('', str) # where to store received files

# debug settings
config['debug.analysis'] =   Option(False, bool)   # stuff relevant to analysis
config['debug.chunks'] =     Option(True, bool)   # stuff relevant to Transfer-Encoding: chunked parsing
config['debug.command'] =    Option(False, bool)   # stuff relevant to user commands
config['debug.config'] =     Option(False, bool)   # stuff relevant to configuration
config['debug.flow'] =       Option(True, bool)   # stuff relevant to program flow
config['debug.mapping'] =    Option(True, bool)   # stuff relevant to local-remote URL mapping
config['debug.parsing'] =    Option(True, bool)   # stuff relevant to request/response parsing
config['debug.protocol'] =   Option(False, bool)   # stuff relevant to protocol decisioning
config['debug.server'] =     Option(True, bool)   # stuff relevant to server management
config['debug.socket'] =     Option(True, bool)   # stuff relevant to socket communication
config['debug.tampering'] =  Option(True, bool)   # stuff relevant to tampering

config['http.no_cache'] = Option(False, bool) # should caching be forcefully disabled?
config['http.drop_request_headers'] = Option('', str) # which headers (separated by spaces) should be dropped?
config['http.drop_response_headers'] = Option('Content-Security-Policy Expect-CT', str) # which headers (separated by spaces) should be dropped?
config['http.recompute_request_length'] = Option(True, bool) # whether request Content-Length should be recomputed before sending to server

config['interaction.realtime_overview'] = Option(True, bool)  # show request/response communication on the fly
config['interaction.command_modifier'] = Option('$', str) # which character would start special sequences (line intervals, less)

# overview settings
config['overview.short_request'] = Option(False, bool) # reduce size of too long URLs
config['overview.show_event'] =    Option(False, bool) # show event ID in overview
config['overview.show_size'] =     Option(True, bool)  # show response size in overview
config['overview.show_time'] =     Option(False, bool) # show forwarded time in overview # TODO also relative?
config['overview.show_uri'] =      Option(True, bool)  # show uri in overview

config['proxy.host'] =     Option('localhost', str, immutable=True)
config['proxy.port'] =     Option(8555, int, immutable=True)
config['proxy.threaded'] = Option(True, bool)

config['spoof.arguments'] = Option(False, bool) # should arguments be taken into consideration for spoofing?

'''



# edit settings
config['edit.command'] = ('vim %s', str)

# http settings
config['http.show_password'] = (False, bool) # should password fields be visible? # TODO implement
config['http.show_hidden'] = (False, bool) # should hidden fields be visible? # TODO implement

# how Weber will interact with user
config['interaction.show_upstream'] = (True, bool) # what version of RR should be presented?

# proxy-relevant settings
config['proxy.sslport'] =  (8556, int)
config['proxy.sslcert'] =  ('cert.pem', str)
config['proxy.sslkey'] =   ('key.pem', str)
config['proxy.default_protocol'] = ('http', str) 

# spoof

# tamper
config['tamper.requests'] =  (False, bool) # should all requests be tampered by default?
config['tamper.responses'] = (False, bool) # should all responses be tampered by default?
'''


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
spoof_request_regexs = {}
spoof_response_regexs = {}

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
Dictionary of Server() objects holding info about RRs, cookies etc.
"""
#servers = OrderedDict()
servers = []
'''
"""
ServerManager instance to thread-safe Server operations
initialized in source/structures.py
"""
serman = None
'''
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

