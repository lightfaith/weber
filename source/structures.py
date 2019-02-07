#!/usr/bin/env python3
"""
Various structures are defined here.
"""
import itertools
import os
import re
import threading
import traceback
from collections import OrderedDict

from source import weber
from source import log
from source.lib import *
from source.protocols import protocols
from source.analysis import analysis
from source.fd_debug import *


class Server():
    """Server object holds information about remote target.
    
    Attributes:

    """
    creation_lock = threading.Lock()
    '''
    @staticmethod
    def get_uri(uri : str):
        """Translates uri (str) into uri (obj:URI), strips everything 
        irrelevant for a Server instance.

        This method is used to test whether a Server with a same name
        already exists without the need to create a new instance. 

        Args:
            uri (str): URI of the target, path will be stripped
        
        Returns:
            uri (obj:URI): Parsed URI
        """
        result = URI(uri)
        result.path = '/'
        return result
    '''
    @staticmethod
    def create_server(uri, protocol):
        """
        Creates a new server instance IF there is not already 
        an appropriate one.

        Returns:
            server_id - ID of Server in weber.servers list
        """
        with Server.creation_lock:
            matching = [s for s in weber.servers if s.uri.tostring() == uri]
            if not matching:
                """new; create one"""
                log.debug_server('Creating new server instance.')
                new_server = Server(uri, protocol)
                weber.servers.append(new_server)
                matching = [new_server]
            else:
                log.debug_server('Using existing server instance') 
            """return index"""
            return weber.servers.index(matching[0])

    def __init__(self, uri, protocol):
        """Creates instance of the Server.
        Args:
            cookies ():
            certificate ():
            ssl (bool): 
            uri (str): URI of the target, path will be stripped
        """
        self.lock = None
        self.uri = URI(uri)
        self.uri.path = ''
        self.protocol = protocol
        self.cookies =  OrderedDict()
        self.certificate_path = None
        self.certificate_key_path = None
        self.real_certificate = None
        self.ssl = self.uri.scheme.endswith('s') # TODO whitelist? Cause IS-IS
        self.problem = False
        
        """setup lock"""
        self.setup_lock()

        """get certificate if ssl"""
        if self.ssl:
            """download real one"""
            import ssl
            from OpenSSL.crypto import FILETYPE_PEM, load_certificate
            try:
                x509 = load_certificate(
                           FILETYPE_PEM, 
                           ssl.get_server_certificate(
                               (self.uri.domain, 
                                self.uri.port)))
            except ConnectionRefusedError:
                log.warn('Connection to %s refused.' % self.uri.tostring())
                self.problem = True
            except Exception as e:
                log.err('Unknown error while getting certificate for %s' 
                         % self.uri.tostring())
                log.err(str(e))
                self.problem = True
            # TODO parse and store important stuff in self.attributes['real_certificate']
            #print('subject', x509.get_subject())
            #for i in range(x509.get_extension_count()):
            #    print('extension', x509.get_extension(i))
            #print('issuer', x509.get_issuer())
            #print('nb', x509.get_notBefore())
            #print('na', x509.get_notAfter())
            #print('pubkey', x509.get_pubkey())
            #print('sn', x509.get_serial_number())
            #print('sigalgo', x509.get_signature_algorithm())
            #print('expi', x509.has_expired())

            """generate fake one (real one is NOT needed for that)"""
            domain = self.uri.domain
            self.certificate_path = ('ssl/pki/issued/%s.crt' % domain)
            self.certificate_key_path = ('ssl/pki/private/%s.key' % domain)
            """already exists?"""
            try:
                with open(self.certificate_path, 'r') as f:
                    pass
            except:
                log.debug_flow('Generating fake certfificate for \'%s\'' % 
                               domain)
                returncode, o, e = run_command('./create_certificate.sh %s' % 
                                               domain)
                if returncode != 0:
                    log.err('Certificate creation failed:')
                    print(o)
                    print(e)

    
    def setup_lock(self):
        self.lock = threading.Lock()

    def get_rps_approval(self):
        """
        Sleeps to limit the request spamming for given server.
        """
        return True # TODO with self.lock sleep 

'''
class ServerManager:
    """
    Class to thread-safe access to server instances.
    Thanks to this Server instances do not have to hold locks and
    therefore are serializable.
    Replaces weber.servers
    """
    # TODO LOCKS EVERYWHERE!!!!!!
    def __init__(self):
        """

        """
        self.__servers = OrderedDict()
    
    def get_key_by_id(self, server_id):
        return list(self.__servers.items())[server_id][0]

    def get_server_by_id(self, server_id):
        return list(self.__servers.items())[server_id][1]

    def get_id(self, uri):
        return list(self.__servers.keys()).index(uri)

    
    def load_servers(self, servers):
        """
        Loads serialized servers
        """
        pass # TODO

    def get(self, server_id, name):
        if name in ('uri', 'ssl'):
            return self.get_server_by_id(server_id).attributes[name]
        else:
            log.err('Cannot get \'%s\' server attribute (not in whitelist).' 
                    % name)

    def set(self, server_id, name, value):
        # TODO whitelist
        pass

    def get_rps_approval(self, server_id):
        self.get_server_by_id(server_id).get_rps_approval()
    # TODO replace weber.servers
    
"""initialize global ServerManager"""
weber.serman = ServerManager()
'''

class URI():
    """Single URI instance.

    Attributes:
        scheme ():
        user ():
        password ():
        domain ()
        port ():
        path ():
    """
    '''
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
    '''     

    def __init__(self, uri, scheme=None):
        self.scheme, self.user, self.password, self.domain, self.port, \
        self.path, self.Protocol = URI.parse(uri)
        '''if scheme is not None:
            self.scheme = scheme
        '''

    def clone(self):
        return URI(self.__bytes__())
    
    def tostring(self, scheme=True, credentials=True, domain=True, 
                 port=True, path=True):
        """

        """
        args = []
        format_strings = []
        """prepare all desired parts"""
        for allowed, value, format_string in (
                (scheme, self.scheme, '%s://'),
                (credentials and self.user and self.password, 
                 '%s:%s' % (self.user, self.password), 
                 '%s@'),
                (domain, self.domain, '%s'),
                (port, self.port, ':%d'),
                (path, self.path, '%s'),
            ):
            if allowed:
                args.append(value)
                format_strings.append(format_string)
        """return prepared stuff"""
        return (''.join(format_strings)) % tuple(args)

    '''        
    def get_value(self, path=True):
        if len(self.user)>0 and len(self.password)>0:
            return '%s://%s:%s@%s:%d%s' % (self.scheme, self.user, self.password, self.domain, self.port, (self.path if path else ''))
        else:
            return '%s://%s:%d%s' % (self.scheme, self.domain, self.port, (self.path if path else ''))
    '''
    '''
    def get_mapping_path(self):
        if self.path.startswith('/WEBER-MAPPING/'):
            return '/'.join(self.path.split('/')[:3])
        else:
            return ''
    '''

    def __str__(self):
        return 'URI(%s)' % (self.tostring()) 
	
    def __bytes__(self):
        return self.tostring().encode()

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
        """
        splits 'https://admin:pasword@example.com:4443/x/y.html' 
        into scheme, user, pass, domain, port and path

        """
        if isinstance(uri, URI):
            uri = uri.tostring()
        elif type(uri) == bytes:
            uri = uri.decode()

        log.debug_protocol('Parsing URI \'%s\'' % (uri))
        Protocol = None

        # get scheme
        if '://' in uri:
            scheme, _, noscheme = uri.partition('://')
            for _, protocol in weber.protocols.items():
                if scheme in (protocol.scheme, protocol.ssl_scheme):
                    log.debug_protocol('  Found protocol by scheme: %s -> %s' %
                                       (scheme, protocol.scheme))
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
                            log.debug_protocol(
                                '  Found protocol by port: %s -> %s' % 
                                (port, protocol.scheme))
                            Protocol = protocol
            else:
                if Protocol:
                    if scheme == Protocol.scheme:
                        port = Protocol.port
                    elif scheme == Protocol.ssl_scheme:
                        port = Protocol.ssl_port
                log.debug_protocol('  Using protocol to get port: %s -> %d' % 
                                   (protocol.scheme, port))
        else:
            domain = domainport
            if not Protocol: # use default value
                log.debug_protocol('  Setting default protocol: %s' % 
                                   (weber.protocols['http']))
                Protocol = weber.protocols.get('http')
            if not Protocol: # bad config
                log.err('Cannot use default protocol.')
                return tuple()
            
            port = (Protocol.ssl_port if scheme == Protocol.ssl_scheme 
                    else Protocol.port)
            
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


class RRDB():
    """
    Database of Request/Response pairs.
    """
    def __init__(self):
        self.rrid = 0 # last rrid
        self.rrs = OrderedDict() # rrid:RR()
        self.lock = None
        self.setup_lock()

    def setup_lock(self):
        self.lock = threading.Lock()
    
    def get_new_rrid(self): # generated in Proxy(), so it is thread-safe
        """

        """
        with self.lock:
            self.rrid += 1
            return self.rrid

    def add_request(self, rrid, request, server, times):
        """

        """
        self.rrs[rrid] = RR(rrid, request, server, times)

    def add_response(self, rrid, response, allow_analysis=True):
        """

        """
        self.rrs[rrid].add_response(response, allow_analysis)
    
    def add_rr(self, rr, update_rr_rrid=False):
        # TODO not refactored
        # used when creating a template => rrid in rr will probably be updated
        rrid = self.get_new_rrid()
        if update_rr_rrid:
            rr.rrid = rrid
        self.rrs[rrid] = rr
        return rrid

    def get_desired_rrs(self, arg, showlast=False, 
                        onlytampered=False, withanalysis=False):
        """
        this method parses rrid specifier (e.g. 1,2,3-5,10)
        returns OrderedDict of (rrid, RR sorted by rrid) and flag 
        whether problem occured
        """
        """rrs empty? don't even try"""
        if not self.rrs.keys():
            return {}
        indices = []
        minimum = 1
        maximum = max(self.rrs.keys())
        noproblem = True
        #pdb.set_trace()
        if arg is not None:
            """argument specified, deal with it"""
            for desired in arg.split(','):
                start = minimum
                end = maximum
                if '-' in desired:
                    """interval"""
                    _start, _, _end = desired.partition('-')
                    if _start.isdigit():
                        start = min([max([start, int(_start)]), end])
                    else:
                        noproblem = False
                    if _end.isdigit():
                        end = max([min([end, int(_end)]), start])
                    else:
                        noproblem = False
                    if start > end:
                        tmp = start
                        start = end
                        end = tmp
                    indices += list(range(start, end+1))
                else:
                    """single value"""
                    if desired.isdigit():
                        indices.append(int(desired))
        else:
            """no RRID specified - use everything"""
            indices = list(range(minimum, maximum+1))[(-10 if showlast else 0):]
        """"""
        keys = [x for x in self.rrs.keys() 
                if (not onlytampered 
                    and (not withanalysis or self.rrs[x].analysis_notes)) 
                or self.rrs[x].request.tampering 
                or (self.rrs[x].response is not None 
                    and self.rrs[x].response.tampering)]
        #print('keys:', keys)
        """return resulting dict and flag"""
        return (OrderedDict([(i, self.rrs[i]) 
                    for i in sorted(indices) if i in keys]), 
                noproblem)

    
    def overview(self, args, header=True, show_event=False, show_size=False, 
                 show_time=False, show_uri=False, show_last=False, 
                 only_tampered=False, only_with_analysis=False):
        """

        """
        show_event = (show_event 
                      or positive(weber.config['overview.show_event'].value))
        show_time = (show_time 
                     or positive(weber.config['overview.show_time'].value))
        show_uri = (show_uri 
                    or positive(weber.config['overview.show_uri'].value))
        show_size = (show_size 
                     or positive(weber.config['overview.show_size'].value))

        result = []
        arg = args[0] if args else None
        #eidlen = max([3]+[len(str(e)) for e,_ in weber.events.items()])
        """find out what to show"""
        desired = self.get_desired_rrs(arg, 
                                       showlast=show_last, 
                                       onlytampered=only_tampered, 
                                       withanalysis=only_with_analysis)
        if not desired:
            return []
        """forget the noproblem flag"""
        desired = desired[0] 

        """create big table with everything desired"""
        table = []
        format_line = '    '

        """header and format string"""
        row = []
        if show_time:
            """time"""
            row.append('Time')
            format_line += '%-*s  '
        if show_event:
            """event"""
            row.append('EID')
            format_line += '%-*s  '
        """RRID"""
        row.append('{0}{0}RRID'.format(log.COLOR_NONE))
        format_line += '%-*s  '
        if show_uri:
            """Server URI"""
            row.append('Server')
            format_line += '%-*s  '
        """Request"""
        row.append('{0}{0}{0}{0}Request'.format(log.COLOR_NONE))
        format_line += '%-*s  '
        """Response"""
        row.append('{0}{0}{0}{0}Response'.format(log.COLOR_NONE))
        format_line += '%-*s  '
        if show_size:
            """Size"""
            row.append('Size')
            format_line += '%*s'

        """use header if desired (e.g. not in realtime overview)"""
        if header:
            table.append(row)
        
        """get lines"""
        for rrid, rr in desired.items():
            row = []
            if show_time:
                """time"""
                time_value = rr.times.get('response_received') # TODO originally request_forwarded...
                row.append(time_value.strftime('%H:%M:%S.%f')[:-3] 
                           if time_value else '')
            if show_event:
                """event"""
                row.append(('%d' % rr.eid) if rr.eid else '')
            row.append(('\033[07m%-4d\033[27m' if rr.analysis_notes 
                        else '\033[00m%-4d\033[00m') % (rrid))
            if show_uri:
                """Server URI"""
                try:
                    row.append(rr.server.uri.tostring()) 
                except:
                    continue
            """Request"""
            row.append(rr.request_string(colored=True))
            """Response"""
            row.append(rr.response_string(colored=True))
            if show_size:
                """Size"""
                try:
                    row.append('%d B' % len(rr.response.data))
                except:
                    row.append('- B')
            """Add into table"""
            table.append(row)

        """get max lengths for each column"""
        color_length = len(log.COLOR_GREEN)+len(log.COLOR_NONE)
        lengths = []

        for i in range(len(table[0])):
            try:
                lengths.append(max([0] + [len(row[i]) for row in table]))
            except Exception as e: # TODO issue if `pr` with EID set
                print(str(e))
                print(table)
                print()
            
        """add border"""
        if header:
            table.insert(1, [])
            for i in range(len(table[0])):
                if table[0][i].endswith('RRID'):
                    border = ('{0}{0}'.format(log.COLOR_NONE)
                              + '='*(lengths[i]-color_length))
                elif table[0][i].endswith(('Request', 'Response')):
                    border = ('{0}{0}{0}{0}'.format(log.COLOR_NONE)
                              + '='*(lengths[i] - 2*color_length))
                else:
                    border = '='*lengths[i]
                table[1].append(border)

        """return pretty lines"""
        for line in table:
            arguments = []
            for i, line in enumerate(line):
                arguments += [lengths[i], line]
            result.append(format_line % tuple(arguments))
        return result

            

weber.rrdb = RRDB()
#weber.tdb = RRDB()

class RR():
    """
    Request/Response pairs, together with other important structures
    """
    #def __init__(self, rrid, request, server, Protocol):
    def __init__(self, rrid, request, server, times):
        """

        """
        self.rrid = rrid
        self.request = request
        self.response = None
        self.server = server
        self.times = times
        self.eid = None # TODO
        #self.Protocol = Protocol
        self.analysis_notes = [] # list of (upstream|downstream, <severity>, <message>) lines
    
    def __str__(self):
        return 'RR(%d --> %s)' % (self.rrid, self.server.uri.tostring())

    def clone(self): # TODO is this needed? ConnectionThread will create everything from scratch...
        """

        """
        #result = RR(self.rrid, self.request.clone(), self.server, self.Protocol)
        result = RR(self.rrid, self.request.clone(), self.server, {})
        if self.response:
            # TODO needed? not for resend nor template...
            result.response = self.response.clone()
        #result.analysis_notes = [x for x in self.analysis_notes] # TODO new analysis, right?
        return result

    def add_response(self, response, allow_analysis=True):
        """

        """
        self.response = response
        """do analysis here if permitted by proxy and desired"""
        if (allow_analysis 
                and positive(weber.config['analysis.immediate'].value) 
                and not self.analysis_notes):
            log.debug_analysis('Running immediate analysis.')
            self.analyze()

    def request_string(self, colored=True):
        """
        
        """
        return self.server.protocol.request_string(self.request, 
                                                   self.response, 
                                                   colored)

    def response_string(self, colored=True):
        """

        """
        return self.server.protocol.response_string(self.response, colored)

    def analyze(self):
        """
        intra-RR analysis
        """

        self.analysis_notes = []
        log.debug_analysis(' Analyzing RR #%d' % (self.rrid))
        """run all known tests except ignored"""
        ignored_tests = weber.config['analysis.ignored_tests'].value.split()
        """for every analysis pack"""
        for name, analysis_pack in weber.analysis.items():
            log.debug_analysis('  using %s' % (name))
            if not analysis_pack['enabled']:
                log.debug_analysis('   NOT enabled, skipping...')
                continue
            """for every Test"""
            for tname, note, protocols, conditions in analysis_pack['rr_tests']:
                """skip ignored"""
                if tname in ignored_tests:
                    continue
                log.debug_analysis('  Trying \'%s\'' % (tname))
                if self.server.protocol.scheme not in protocols:
                    """skip if incorrect protocol"""
                    log.debug_analysis('   NOT supported for this protocol,'
                                       'skipping...')
                    continue
                try:
                    match = True
                    """for every condition in the Test"""
                    for comment, condition in conditions:
                        result = bool(condition(self.request, 
                                                self.response, 
                                                self.server))
                        log.debug_analysis('    checking \'%s\': %s' 
                                           % (comment, str(result)))
                        if not result:
                            match = False
                            break
                    # and remember found issues
                    if match:
                        log.debug_analysis('    MATCH => %s: %s' 
                                           % (note[0], note[1]))
                        self.analysis_notes.append((tname, *note))
                except Exception as e:
                    log.debug_analysis('!!! "%s" test failed for RR #%d: %s' 
                                       % (tname, self.rrid, str(e)))
                    traceback.print_exc()
    
    def __repr__(self):
        return 'RR(%d)' % self.rrid

'''
"""
Local-Remote URI mapping
"""
class Mapping():
    def __init__(self):
        self.l_r = OrderedDict() # local->remote
        self.r_l = OrderedDict() # remote->local
        self.map = {}            # bytes->URI
        self.counter = 1
        self.lock = None
        self.Protocol = None
        
        self.setup_lock()

    def setup_lock(self):
        self.lock = threading.Lock()

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

    def get_mapping_id(self, local):
        log.debug_mapping('Getting mapping ID for %s' % local.get_value())
        root_uri = local.clone()
        if root_uri.path.startswith('/WEBER-MAPPING/'):
            root_uri.path = '/'.join(local.path.split('/')[:3]+[''])
        else:
            root_uri.path = '/'
        log.debug_mapping('  which is %s' % root_uri.get_value())

        try:
            mapping_id = list(self.l_r.keys()).index(self.map[root_uri.__bytes__()])
        except:
            log.err('get_mapping_id failed!')
            mapping_id = -1
        log.debug_mapping('  which has index %d' % mapping_id)
        return mapping_id

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
'''

"""
Event
"""
class Event():
    def __init__(self, eid):
        self.eid = eid
        self.rrids = set()
        self.type = ''

'''
class Server():
    """
    The Server class represents remote endpoint. It holds the URI, list of relevant RRs, cookies etc.
    Only RRs really sent to/from the server are here.
    """
    def __init__(self, uri):
        self.uri = uri
        self.rrs = {}
        self.structures = {}


    def add_rr(self, rr):
        self.rrs[rr.rrid] = rr

''' 
