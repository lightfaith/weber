#!/usr/bin/env python3
"""
Various structures are defined here.
"""
import threading, traceback, re, os, itertools
from collections import OrderedDict

from source import weber
from source import log
from source.lib import *
from source.protocols import protocols
from source.analysis import analysis
from source.fd_debug import *


"""
Database of Request/Response pairs.
"""
class RRDB():
    def __init__(self):
        self.rrid = 0 # last rrid
        self.rrs = OrderedDict() # rrid:RR()
        self.lock = threading.Lock()
    
    def get_new_rrid(self): # generated in Proxy(), so it is thread-safe
        with self.lock:
            self.rrid += 1
            return self.rrid

    def add_request(self, rrid, request_downstream, request_upstream, Protocol):
        self.rrs[rrid] = RR(rrid, request_downstream, request_upstream, Protocol)

    def add_response(self, rrid, response_upstream, response_downstream, allow_analysis=True):
        self.rrs[rrid].add_response(response_upstream, response_downstream, allow_analysis)
    
    def add_rr(self, rr):
        rrid = self.get_new_rrid()
        self.rrs[rrid] = rr
        return rrid

    def get_desired_rrs(self, arg, showlast=False, onlytampered=False):
        # this method parses rrid specifier (e.g. 1,2,3-5,10)
        # returns OrderedDict of rrid, RR sorted by rrid and flag whether problem occured
        if len(self.rrs.keys()) == 0:
            return {}
        indices = []
        minimum = 1
        maximum = max(self.rrs.keys())
        noproblem = True
        if arg is not None:
            for desired in arg.split(','):
                start = minimum
                end = maximum
                
                if '-' in desired:
                    _start, _, _end = desired.partition('-')
                else:
                    _start = _end = desired
                if _start.isdigit():
                    start = max([start, int(_start)])
                else:
                    noproblem = False
                if _end.isdigit():
                    end = min([end, int(_end)])
                else:
                    noproblem = False
                if start > end:
                    tmp = start
                    start = end
                    end = tmp
                indices += list(range(start, end+1))
        else:
            indices = list(range(minimum, maximum+1))[(-10 if showlast else 0):]
       
        if positive(weber.config['interaction.showupstream'][0]):
            keys = [x for x in self.rrs.keys() if not onlytampered or self.rrs[x].request_upstream.tampering or (self.rrs[x].response_upstream is not None and self.rrs[x].response_upstream.tampering)]
        else:
            keys = [x for x in self.rrs.keys() if not onlytampered or self.rrs[x].request_downstream.tampering or (self.rrs[x].response_downstream is not None and self.rrs[x].response_downstream.tampering)]
        return (OrderedDict([(i, self.rrs[i]) for i in sorted(indices) if i in keys]), noproblem)

    
    def overview(self, args, header=True, showlast=False, onlytampered=False):
        result = []
        arg = None if len(args)<1 else args[0]
        eidlen = max([3]+[len(str(e)) for e,_ in weber.events.items()])
        desired = self.get_desired_rrs(arg, showlast=showlast, onlytampered=onlytampered)
        if not desired:
            return []
        desired = desired[0]
        reqlen = max([20]+[1+len(v.request_string(colored=True)) for v in desired.values()])
        
        # TODO size, time if desired
        if header:
            hreqlen = reqlen-2*(len(log.COLOR_GREEN)+len(log.COLOR_NONE))
            log.tprint('    %-*s  RRID  %-*s  Response' % (eidlen, 'EID', hreqlen, 'Request'))
            log.tprint('    %s  ====  %-*s  =====================' % ('='*eidlen, hreqlen, '='*hreqlen))

        for rrid, rr in desired.items():
            rr_id = ('\033[7m%-4d\033[0m' if rr.analysis_notes else '%-4d') % (rrid)
            result.append('    %-*s  %s  %-*s  %-20s' % (eidlen, '' if rr.eid is None else rr.eid, rr_id, reqlen, rr.request_string(colored=True), rr.response_string(colored=True)))
        return result

            

weber.rrdb = RRDB()
weber.tdb = RRDB()

"""
Request/Response pairs (both downstream and upstream versions)
"""
class RR():
    def __init__(self, rrid, request_downstream, request_upstream, Protocol):
        self.rrid = rrid
        self.request_downstream = request_downstream
        self.request_upstream = request_upstream
        self.response_upstream = None
        self.response_downstream = None
        self.uri_downstream = None
        self.uri_upstream = None
        self.eid = None
        self.Protocol = Protocol
        self.analysis_notes = [] # list of (upstream|downstream, <severity>, <message>) lines
    
    def clone(self):
        result = RR(self.rrid, self.request_downstream.clone(), self.request_upstream.clone(), self.Protocol)
        if self.response_upstream is not None:
            result.response_upstream = self.response_upstream.clone()
            result.response_upstream.tampering = False
        if self.response_downstream is not None:
            result.response_downstream = self.response_downstream.clone()
            result.response_downstream.tampering = False
        if self.uri_upstream is not None:
            result.uri_upstream = self.uri_upstream.clone()
        if self.uri_downstream is not None:
            result.uri_downstream = self.uri_downstream.clone()
        result.analysis_notes = [x for x in self.analysis_notes]
        return result

    def __str__(self):
        return 'RR(%s <--> %s)' % (self.uri_downstream, self.uri_upstream)

    def add_response(self, response_upstream, response_downstream, allow_analysis=True):
        self.response_upstream = response_upstream
        self.response_downstream = response_downstream
        # do analysis here if permitted by proxy (upstream->downstream already done) and if desired
        if allow_analysis and weber.config['analysis.immediate'][0] and not self.analysis_notes:
            log.debug_analysis('Running immediate analysis.')
            self.analyze()

    
    def request_string(self, colored=True):
        req = self.request_upstream if weber.config['interaction.showupstream'][0] else self.request_downstream
        res = self.response_upstream if weber.config['interaction.showupstream'][0] else self.response_downstream
        return self.Protocol.request_string(req, res, colored)
    
    def response_string(self, colored=True):
        res = self.response_upstream if weber.config['interaction.showupstream'][0] else self.response_downstream
        return self.Protocol.response_string(res, colored)

    def analyze(self): # intra-RR analysis
        # for both upstream and downstream
        for source, req, res, uri in (('upstream', self.request_upstream, self.response_upstream, self.uri_upstream), ('downstream', self.request_downstream, self.response_downstream, self.uri_downstream)):
            log.debug_analysis(' Analyzing %s' % (source))
            # run all known tests
            for name, analysis in weber.analysis.items():
                log.debug_analysis('  using %s' % (name))
                if not analysis['enabled']:
                    log.debug_analysis('   NOT enabled, skipping...')
                    continue

                for testname, supported, test in analysis['rr_tests']:
                    log.debug_analysis('  Trying \'%s\'' % (testname))
                    if self.Protocol.scheme not in supported:
                        log.debug_analysis('   NOT supported for this protocol, skipping...')
                        continue
                    try:
                        note = test(req, res, uri)
                        # and remember found issues
                        if note:
                            log.debug_analysis('  MATCH => %s: %s' % (note[0], note[1]))
                            self.analysis_notes.append((source, *note))
                    except Exception as e:
                        log.debug_analysis('"%s" test failed for RR #%d (%s): %s' % (testname, self.rrid, source, str(e)))
    

"""
Local-Remote URI mapping
"""
class Mapping():
    def __init__(self):
        self.l_r = OrderedDict() # local->remote
        self.r_l = OrderedDict() # remote->local
        self.map = {}            # bytes->URI
        self.counter = 1
        self.lock = threading.Lock()
        self.Protocol = None

    def add_init(self, remote): # add first known local
        # learn protocol from scheme or port
        givenuri = URI(remote, None)
        self.Protocol = givenuri.Protocol

        # TODO update with regard to protocol
        nossl_r = URI(remote, self.Protocol.scheme)
        ssl_r = URI(remote, self.Protocol.ssl_scheme)
        nossl_r.port = self.Protocol.port if givenuri.scheme != self.Protocol.scheme else givenuri.port
        ssl_r.port = self.Protocol.ssl_port if givenuri.scheme != self.Protocol.ssl_scheme else givenuri.port
        nossl_l = '%s://%s:%d' % (self.Protocol.scheme, weber.config['proxy.host'][0], weber.config['proxy.port'][0])
        ssl_l = '%s://%s:%d' % (self.Protocol.ssl_scheme, weber.config['proxy.host'][0], weber.config['proxy.sslport'][0])
        self.add(nossl_l, nossl_r.get_value())
        self.add(ssl_l, ssl_r.get_value())

    
    def add(self, local, remote): # add known local
        l = URI(local)
        r = URI(remote)
        self.map[l.__bytes__()] = l
        self.map[r.__bytes__()] = r
        self.l_r[l] = r
        self.r_l[r] = l
        return (l, r)

    
    def get_local(self, remote):
        if remote is None:
            return None
        if type(remote) in (str, bytes):
            remote = URI(remote)
        
        log.debug_mapping('get_local() for %s' % (remote.get_value()))
        with self.lock:
            # create new domain mapping if no match, else use existing
            realpath = remote.path
            remote.path = '/'
            if remote.__bytes__() not in self.map.keys():
                # generate brand new - new domain etc.
                self.counter += 1
                port = weber.config['proxy.port' if remote.scheme == 'http' else 'proxy.sslport'][0]
                localroot = '%s://%s:%d/WEBER-MAPPING/%d/' % (remote.scheme, weber.config['proxy.host'][0], port, self.counter)
                localroot, _ = self.add(localroot, remote)
                log.debug_mapping('get_local():   generated new mapping: '+str(localroot)+' <--> '+str(remote))
            else:
                # get existing
                localroot = self.r_l[self.map[remote.__bytes__()]]
            # alter the path
            remote.path = realpath
            local = localroot.clone()
            log.debug_mapping('get_local():   using localroot '+localroot.get_value())
            local.path += realpath[1:] # without the leading slash - already present in local.path
            log.debug_mapping('get_local():   %s --> %s' % (remote.get_value(), local.get_value()))
            return local
                
        
    def get_remote(self, local):
        remote = None
        if local is None:
            return remote
        if not isinstance(local, URI):
            local = URI(local)
        else:
            # work with clone
            local = local.clone()
        
        orig_str = str(local)

        log.debug_mapping('get_remote() for %s' % (local.get_value()))
        if local.path.startswith('/WEBER-MAPPING/'):
            realpath = '/'+'/'.join(local.path.split('/')[3:])
            local.path = '/'.join(local.path.split('/')[:3]+[''])
        else:
            realpath = local.path
            local.path = '/'
        if local.__bytes__() in self.map.keys():
            remote = self.l_r[self.map[local.__bytes__()]].clone()
            remote.path += realpath[1:] # without the leading slash - already present in remote.path
        local.path = realpath
        log.debug_mapping('get_remote():   %s --> %s' % (orig_str, str(remote)))
        return remote

    
    def uri_is_mapped(self, uri):
        if not isinstance(uri, URI):
            uri = URI(uri).clone()
        uri.path = '/'
        return uri.__bytes__() in self.map.keys()


weber.mapping = Mapping()

"""
Single URI
"""
class URI():
    @staticmethod
    def build_str(domain, port, path=b'/', Protocol=None, scheme=None, user=None, password=None):
        if isinstance(domain, str):
            domain = domain.encode()
        if not port:
            port = weber.config['proxy.port'][0]
        port = int(port)
        if scheme is None:
            if port == weber.config['proxy.port'][0]:
                scheme = Protocol.scheme.encode() if Protocol else weber.config['proxy.default_protocol'][0].encode()
            elif port == weber.config['proxy.sslport'][0]:
                scheme = Protocol.ssl_scheme.encode() if Protocol else weber.protocols[weber.config['proxy.default_protocol'][0]].encode()
        if scheme is None:
            log.err('Cannot build_str() - unknown port.')
            return ''
        if user is None and password is None:
            return (b'%s://%s:%d%s' % (scheme, domain, port, path)).decode()
        elif user is not None and password is not None:
            return (b'%s://%s:%s@%s:%d%s' % (scheme, domain, port, path)).decode()
        else:
            log.err('Cannot build_str() - user or pass not defined.')
            return ''
            

    def __init__(self, uri, scheme=None):
        self.scheme, self.user, self.password, self.domain, self.port, self.path, self.Protocol = URI.parse(uri)
        if scheme is not None:
            self.scheme = scheme

    def clone(self):
        return URI(self.__bytes__())

    def get_value(self):
        if len(self.user)>0 and len(self.password)>0:
            return '%s://%s:%s@%s:%d%s' % (self.scheme, self.user, self.password, self.domain, self.port, self.path)
        else:
            return '%s://%s:%d%s' % (self.scheme, self.domain, self.port, self.path)
        
    def __str__(self):
        return 'URI(%s)' % (self.get_value()) 
	
    def __bytes__(self):
        return self.get_value().encode()

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def port_is_explicit(uri):
        # returns whether port is specified or not
        if type(uri) == bytes:
            uri = uri.decode()
        if '://' in uri:
            _, _, noscheme = uri.partition('://')
        if '@' in noscheme:
            _, _, domainport = noscheme.partition('@')
        if ':' in domainport:
            _, _, port = domainport.partition(':')
        return port.isdigit()


    @staticmethod
    def parse(uri):
        # splits https://admin:pasword@example.com:4443/x/y.html into scheme, user, pass, domain, port and path
        if isinstance(uri, URI):
            uri = uri.get_value()
        elif type(uri) == bytes:
            uri = uri.decode()

        log.debug_protocol('Parsing URI \'%s\'' % (uri))
        Protocol = None

        # get scheme
        if '://' in uri:
            scheme, _, noscheme = uri.partition('://')
            for _, protocol in weber.protocols.items():
                if scheme in (protocol.scheme, protocol.ssl_scheme):
                    log.debug_protocol('  Found protocol by scheme: %s -> %s' % (scheme, protocol.scheme))
                    Protocol = protocol
        else:
            scheme = None
            #scheme = Protocol.scheme # unknown, decide from port
            noscheme = uri

        # get domainport and path
        domainport, _, path = noscheme.partition('/')

        # users?
        if '@' in domainport:
            creds, _, domainport = domainport.partition('@')
            user, _, password = creds.partition(':')
        else:
            user = ''
            password = ''

        # domain, port
        if ':' in domainport:
            domain, _, port = domainport.partition(':')
            if port.isdigit():
                port = int(port)
                if not Protocol:
                    for _, protocol in weber.protocols.items():
                        if int(port) in (protocol.port, protocol.ssl_port):
                            log.debug_protocol('  Found protocol by port: %s -> %s' % (port, protocol.scheme))
                            Protocol = protocol
            else:
                if Protocol:
                    if scheme == Protocol.scheme:
                        port = Protocol.port
                    elif scheme == Protocol.ssl_scheme:
                        port = Protocol.ssl_port
                log.debug_protocol('  Using protocol to get port: %s -> %d' % (protocol.scheme, port))
        else:
            domain = domainport
            if not Protocol: # use default value
                log.debug_protocol('  Setting default protocol: %s' % (weber.config['proxy.default_protocol'][0]))
                Protocol = weber.protocols.get(weber.config['proxy.default_protocol'][0])
            if not Protocol: # bad config
                log.err('Unknown default protocol \'%s\'' % (weber.config['proxy.default_protocol'][0]))
                return tuple()
            
            port = Protocol.ssl_port if scheme == Protocol.ssl_scheme else Protocol.port
            
            #port = Protocol.ssl_port if scheme == Protocol.ssl_scheme else Protocol.port # default
        
        if not scheme:
            for Protocol in weber.protocols.values():
                if port == Protocol.port:
                    scheme = Protocol.scheme
                    break
                elif port == Protocol.ssl_port:
                    scheme = Protocol.ssl_scheme
                    break

        if not scheme:
            log.err('Cannot get scheme for \'%s\'' % (uri))
            return tuple()
        return (scheme, user, password, domain, int(port), '/'+path, Protocol)


"""
Event
"""
class Event():
    def __init__(self, eid):
        self.eid = eid
        self.rrids = set()
        self.type = ''

