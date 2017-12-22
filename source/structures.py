#!/usr/bin/env python3
"""
Various structures are defined here.
"""
import threading, traceback, re, os, itertools
from collections import OrderedDict

from source import weber
from source import log
from source.lib import *


class Request():
    """
    HTTP Request class
    """
    def __init__(self, data, should_tamper):
        """
            data = request data (bytes)
            should_tamper = should the request be tampered? (bool)
        """
        self.integrity = False
        if not data:
            return
        
        # set up tampering mechanism
        self.should_tamper = should_tamper
        #self.forward_stopper = os.pipe() if forward_stopper is None else forward_stopper
        self.forward_stopper = os.pipe()
        self.tampering = self.should_tamper
        
        # parse data
        self.parse(data)

        # allow forwarding immediately?
        if not self.should_tamper:
            self.forward()


    def parse(self, data):
        # parse given bytes (from socket, editor, file, ...)
        self.original = data
        lines = data.splitlines()
        self.method, self.path, self.version = tuple(lines[0].split(b' '))
        self.parameters = {}
        
        self.headers = OrderedDict()
        self.data = b''
        for line in lines[1:-1]:
            if not line:
                continue
            k, _, v = line.partition(b':')
            # TODO duplicit keys? warn
            self.headers[k] = v.strip()
           
        if len(lines[-1]) > 0:
            self.data = lines[-1]

        self.parse_method()
        self.integrity = True

    
    def sanitize(self):
        # alter the Request so we don't have to deal with problematic options, e.g. encoding
        # should not be used on the original (downstream) Request

        # disable encoding
        self.headers.pop(b'Accept-Encoding', None)
        # disable Range
        self.headers.pop(b'Range', None)
        self.headers.pop(b'If_Range', None)


    def clone(self, should_tamper=False):
        return Request(self.bytes(), should_tamper) 

    def forward(self):
        self.tampering = False
        os.write(self.forward_stopper[1], b'1')

    def parse_method(self):
        # GET, HEAD method
        if self.method in [b'GET', b'HEAD']:
            self.onlypath, _, tmpparams = self.path.partition(b'?')
            for param in tmpparams.split(b'&'):
                if param == b'':
                    continue
                k, _, v = tuple(param.partition(b'='))
                v = None if v == b'' else v
                self.parameters[k] = v
        # POST method
        if self.method in [b'POST']:
            self.onlypath, _, _ = self.path.partition(b'?')
            for param in self.data.split(b'&'):
                if param == b'':
                    continue
                k, _, v = param.partition(b'=')
                v = None if v == b'' else v
                self.parameters[k] = v
        # TODO more methods



    def lines(self, headers=True, data=True, as_string=True):
        parts = []
        
        if headers:
            parts.append(b'%s %s %s' % (self.method, self.path, self.version))
            parts += [b'%s: %s' % (k, '' if v is None else v) for k, v in self.headers.items()]
            if data:
                parts.append(b'')
        if data:
            parts += self.data.split(b'\n')
        try:
            parts = [x.decode() for x in parts] if as_string else parts
        except Exception as e:
            log.warn('Response encoding problem occured: '+str(e))
            parts = []
        return parts
        

    def __str__(self):
        return '\n'.join(self.lines())

    def bytes(self):
        result = b'%s %s %s\r\n' % (self.method, self.path, self.version)
        result += b'\r\n'.join([b'%s: %s' % (k, b'' if v is None else v) for k, v in self.headers.items()])
        result += b'\r\n\r\n'
        if len(self.data)>0:
            result += self.data
        return result









class Response():
    link_tags = [
        (b'<a', b'</a>', b'href'),
        (b'<form', b'</form>', b'action'),
        (b'<frame', b'</frame>', b'src'),
        (b'<img', b'>', b'src'),
        (b'<script', b'>', b'src'),
    ] # TODO more

    def __init__(self, data, should_tamper):
        # set up tampering mechanism
        self.should_tamper = should_tamper
        #self.forward_stopper = os.pipe() if forward_stopper is None else forward_stopper
        self.forward_stopper = os.pipe()
        self.tampering = should_tamper
        
        # parse data
        self.parse(data)

        # allow forwarding?
        if not self.should_tamper:
            self.forward()
    
    
    def parse(self, data):
        # parse given bytes (from socket, editor, file, ...)
        self.original = data
        lines = data.split(b'\r\n')
        self.version = lines[0].partition(b' ')[0]
        self.statuscode = int(lines[0].split(b' ')[1])
        self.status = b' '.join(lines[0].split(b' ')[2:])
        self.headers = OrderedDict()

        # load first set of headers (hopefully only one)
        line_index = 1
        for line_index in range(1, len(lines)):
            line = lines[line_index]
            if len(line) == 0:
                break
            k, _, v = line.partition(b':')
            self.headers[k] = v.strip()
        
        line_index += 1

        # chunked Transfer-Encoding?
        data_line_index = line_index # backup the value
        try:
            self.data = b''
            while True: # read all chunks
                log.debug_chunks('trying to unchunk next chunk...')
                log.debug_chunks('next line: %s' % (str(lines[line_index])))
                chunksize = int(lines[line_index], 16)
                log.debug_chunks('chunksize (parsed): 0x%x' % (chunksize))
                if chunksize == 0: # end of stream
                    log.debug_chunks('unchunking finished.')
                    break
                tmpchunk = b''
                while True: # read all bytes for chunk
                    line_index += 1
                    tmpchunk += lines[line_index]
                    if len(tmpchunk) == chunksize: # chunk is complete
                        log.debug_chunks('end of chunk near %s' % str(lines[line_index][-30:]))
                        line_index += 1
                        break
                    if len(tmpchunk) > chunksize: # problem...
                        log.warn('Loaded chunk is bigger than advertised: %d > %d' % (len(tmpchunk), chunksize))
                        break
                    # chunk spans multiple lines...
                    tmpchunk += b'\r\n'
                self.data += tmpchunk
        except Exception as e:
            line_index = data_line_index # restore the value
            log.debug_chunks('unchunking failed:')
            log.debug_chunks(e)
            #traceback.print_exc()
            log.debug_chunks('treating as non-chunked...')
            # treat as normal data
            self.data = b'\r\n'.join(lines[line_index:])
            # TODO test for matching Content-Type (HTTP Response-Splitting etc.)
        
    
    def sanitize(self):
        # alter the Response so we don't have to deal with problematic options, e.g. chunked
        # should NOT be used on the original (upstream) Response
        
        # strip Transfer-Encoding...
        self.headers.pop(b'Transfer-Encoding', None)
        
        # no wild upgrading (HTTP/2)
        self.headers.pop(b'Upgrade', None)


    def clone(self, should_tamper=True):
        return Response(self.bytes(), should_tamper) 

    def forward(self):
        self.tampering = False
        os.write(self.forward_stopper[1], b'1')
 
    def compute_content_length(self):
        #if b'Content-Length' not in self.headers.keys() and len(self.data)>0:
        log.debug_parsing('Computing Content-Length...')
        self.headers[b'Content-Length'] = b'%d' % (len(self.data))

    def lines(self, headers=True, data=True, as_string=True):
        parts = []
        if headers:
            self.compute_content_length()
            parts.append(b'%s %d %s' % (self.version, self.statuscode, self.status))
            parts += [b'%s: %s' % (k, '' if v is None else v) for k, v in self.headers.items()]
            if data:
                parts.append(b'')
        if data:
            # Do not include if string is desired and it is binary content
            # TODO more Content-Types
            if as_string and self.statuscode < 300 and (b'Content-Type' not in self.headers or (b'Content-Type' in self.headers and not self.headers[b'Content-Type'].startswith((b'text/', b'application/')))):
                parts.append(b'--- BINARY DATA ---')
            else:
                parts += self.data.split(b'\n')
            
        try:
            parts = [x.decode('utf-8', 'replace') for x in parts] if as_string else parts # not accurate
        except Exception as e:
            log.warn('Response encoding problem occured: %s' % (str(e)))
            log.warn('For '+str(self.headers))
            parts = []
        return parts

    def __str__(self):
        return '\n'.join(self.lines())

    def bytes(self):
        self.compute_content_length()
        #data = lib.gzip(self.data) if self.headers.get(b'Content-Encoding') == b'gzip'  else self.data
        result = b''
        result += b'%s %d %s\r\n' % (self.version, self.statuscode, self.status)
        result += b'\r\n'.join([b'%s: %s' % (k, b'' if v is None else v) for k, v in self.headers.items()])
        
        result += b'\r\n\r\n' + self.data + b'\r\n\r\n'
        return result
    
    def find_html_attr(self, tagstart, tagend, attr):
        # this method uses find_between() method to locate attributes and their values for specified tag
        # returns list of (absolute_position, match_string) of attributes
        tagmatches = find_between(self.data, tagstart, tagend)
        result = []
        for pos, _ in tagmatches:
            # find the end of the tagstart
            endpos = self.data.index(b'>', pos)
            linkmatches = find_between(self.data, b'%s="' % (attr), b'"', startpos=pos, endpos=endpos, inner=True)
            #if not linkmatches: # try without '"' # TODO should be done, but how to get good loffset in self.replace_links()?
            #    linkmatches = find_between(self.data, b'%s=' % (attr), b' ', startpos=pos, endpos=endpos, inner=True)
            result += linkmatches
        return result

    def replace_links(self, tagstart, tagend, attr):
        # this method searches desired tag attributes using find_html_attr() and replaces its content
        # result is directly written into self.data
        oldparts = [] # unchanged HTML chunks
        loffset = 0
        linkmatches = self.find_html_attr(tagstart, tagend, attr)
        for roffset, value in linkmatches:
            # add chunk until match
            oldparts.append(self.data[loffset:roffset])
            # prepare for new chunk
            loffset = roffset+len(attr) + 2 + len(value) + 1
            #                  href       =" index.html    "
        # add last chunk
        oldparts.append(self.data[loffset:])

        # get new values if desired
        newparts = [b'%s="%s"' % (attr, (x[1] if not x[1].partition(b'://')[0] in (b'http', b'https') else weber.mapping.get_local(x[1]))) for x in linkmatches]
        # join oldparts and newparts
        result = filter(None, [x for x in itertools.chain.from_iterable(itertools.zip_longest(oldparts, newparts))])
        self.data = b''.join(result)


    def spoof(self, path):
        # replace data with file content
        try:
            with open(path, 'rb') as f:
                self.data = f.read()
            self.statuscode = 200
            self.status = b'OK'
            self.compute_content_length()
        except:
            log.err('Spoofing failed - cannot open file.')







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

    def add_request(self, rrid, request_downstream, request_upstream):
        self.rrs[rrid] = RR(request_downstream, request_upstream)

    def add_response(self, rrid, response_upstream, response_downstream):
        self.rrs[rrid].add_response(response_upstream, response_downstream)
    
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
       
        if positive(weber.config['tamper.showupstream'][0]):
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
            result.append('    %-*s  %-4d  %-*s  %-20s' % (eidlen, '' if rr.eid is None else rr.eid, rrid, reqlen, rr.request_string(colored=True), rr.response_string(colored=True)))
        return result

            

weber.rrdb = RRDB()
weber.tdb = RRDB()

"""
Request/Response pairs (both downstream and upstream versions)
"""
class RR():
    def __init__(self, request_downstream, request_upstream):
        self.request_downstream = request_downstream
        self.request_upstream = request_upstream
        self.response_upstream = None
        self.response_downstream = None
        self.uri_downstream = None
        self.uri_upstream = None
        self.eid = None
    
    def clone(self):
        result = RR(self.request_downstream.clone(), self.request_upstream.clone())
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
        return result

    def __str__(self):
        return 'RR(%s <--> %s)' % (self.uri_downstream, self.uri_upstream)

    def add_response(self, response_upstream, response_downstream):
        self.response_upstream = response_upstream
        self.response_downstream = response_downstream

    def request_string(self, colored=False):
        req = self.request_upstream if positive(weber.config['tamper.showupstream'][0]) else self.request_downstream
        if True:#try:
            # TODO also from Accept:
            tamperstring = ''
            if req.tampering:
                tamperstring = '[T] '
            color = log.COLOR_NONE
            if req.onlypath == b'/' or req.onlypath.endswith((b'.htm', b'.html', b'.php', b'.xhtml', b'.aspx')):
                color = log.COLOR_GREY
            elif req.onlypath.endswith((b'.jpg', b'.svg', b'.png', b'.gif', b'.ico', b'.mp3', b'.ogg', b'.mp4', b'.wav')):
                color = log.COLOR_PURPLE
            elif req.onlypath.endswith((b'.js', b'.vbs', b'.swf')):
                color = log.COLOR_BLUE
            elif req.onlypath.endswith((b'.css')):
                color = log.COLOR_DARK_PURPLE
            elif req.onlypath.endswith((b'.pdf', b'.doc', b'.docx', b'.xls', b'.xlsx', b'.ppt', b'.pptx', b'.pps', b'.ppsx', b'.txt')):
                color = log.COLOR_GREEN
            elif req.onlypath.endswith((b'.zip', b'.7z', b'.rar', b'.gz', b'.bz2', b'.jar', b'.bin', b'.iso')):
                color = log.COLOR_BROWN
            if not colored:
                color = log.COLOR_NONE
            return '%s%s%s%s%s %s%s' % (log.COLOR_YELLOW, tamperstring, log.COLOR_NONE, color, req.method.decode(), req.path.decode(), log.COLOR_NONE)
        if False:#except:
            return log.COLOR_YELLOW+log.COLOR_NONE+log.COLOR_GREY+'...'+log.COLOR_NONE

    def response_string(self, colored=False):
        res = self.response_upstream if positive(weber.config['tamper.showupstream'][0]) else self.response_downstream
        try:
            tamperstring = ''
            if res.tampering:
                tamperstring = '[T] '
            if res.statuscode < 200:
                color = log.COLOR_NONE
            elif res.statuscode == 200:
                color = log.COLOR_DARK_GREEN
            elif res.statuscode < 300:
                color = log.COLOR_GREEN
            elif res.statuscode < 400:
                color = log.COLOR_BROWN
            elif res.statuscode < 500:
                color = log.COLOR_DARK_RED
            elif res.statuscode < 600:
                color = log.COLOR_DARK_PURPLE
            else:
                color = log.COLOR_NONE
            if not colored:
                color = log.COLOR_NONE
            
            return '%s%s%s%s%d %s%s' % (log.COLOR_YELLOW, tamperstring, log.COLOR_NONE, color, res.statuscode, res.status.decode(), log.COLOR_NONE)
        except:
            return log.COLOR_YELLOW+log.COLOR_NONE+log.COLOR_GREY+'...'+log.COLOR_NONE
        

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
    
    def add_init(self, remote): # add first known local
        givenuri = URI(remote)

        http_r = URI(remote, 'http')
        https_r = URI(remote, 'https')
        http_r.port = 80 if givenuri.scheme != 'http' else givenuri.port
        https_r.port = 443 if givenuri.scheme != 'https' else givenuri.port
        http_l = 'http://%s:%d' % (weber.config['proxy.host'][0], weber.config['proxy.port'][0])
        https_l = 'https://%s:%d' % (weber.config['proxy.host'][0], weber.config['proxy.sslport'][0])
        self.add(http_l, http_r.get_value())
        self.add(https_l, https_r.get_value())

    
    def add(self, local, remote): # add known local
        l = URI(local)
        r = URI(remote)
        self.map[l.__bytes__()] = l
        self.map[r.__bytes__()] = r
        self.l_r[l] = r
        self.r_l[r] = l
        return (l, r)

    
    def get_local(self, remote):
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
        if not isinstance(local, URI):
            local = URI(local)

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
        log.debug_mapping('get_remote():   %s --> %s' % (str(local), str(remote)))
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
    def build_str(domain, port, path, scheme=None, user=None, password=None):
        if not port:
            port = weber.config['proxy.port'][0]
        port = int(port)
        if scheme is None:
            if port == weber.config['proxy.port'][0]:
                scheme = b'http'
            elif port == weber.config['proxy.sslport'][0]:
                scheme = b'https'
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
        self.scheme, self.user, self.password, self.domain, self.port, self.path = URI.parse(uri)
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

        # get scheme
        if '://' in uri:
            scheme, _, noscheme = uri.partition('://')
        else:
            scheme = 'http' # default
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
            if not port.isdigit():
                port = 80
        else:
            domain = domainport
            port = 443 if scheme == 'https' else 80 # default
        
        return (scheme, user, password, domain, int(port), '/'+path)

"""
Event
"""
class Event():
    def __init__(self, eid):
        self.eid = eid
        self.rrids = set()
        self.type = ''

