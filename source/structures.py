#!/usr/bin/env python3
"""
Various structures are defined here.
"""
from source import weber
from source import log
from source import lib

import codecs, threading
from collections import OrderedDict


class Request():
    def __init__(self, data):
        self.integrity = False
        if len(data) == 0:
            return
        self.original = data
        lines = data.splitlines()
        self.method, self.path, self.version = tuple(lines[0].split(b' '))
        """self.method, wanted, self.version = tuple(lines[0].split(b' '))
        # parse uri
        parts = wanted.split(b'/')
        if wanted.startswith(b'http'):
            proto = parts[0][:-1]   # e.g. http
            self.host = parts[2].partition(b':')[0] # e.g. 'google.com'
            self.port = parts[2].partition(b':')[2] # e.g. '443'
        else:
            proto = 'http' # default
            self.host = parts[0].partition(b':')[0] # e.g. 'google.com'
            self.port = parts[0].partition(b':')[2] # e.g. '443'
        if self.port == '' or not self.port.isdigit() or int(self.port)>65535 or int(self.port) < 1:
            if proto == b'http':
                self.port = 80
            elif proto == b'https':
                self.port = 443
            else: # default
                self.port = 80
        else:
            self.port = int(self.port)
        self.path = b''.join([b'/'+part for part in parts[3:]])
        """
        
        
        self.headers = OrderedDict()
        self.data = b''
        for line in lines[1:-1]:
            if len(line) == 0:
                continue
            k, _, v = line.partition(b':')
            # TODO duplicit keys? warn
            self.headers[k] = v.strip()
            
        # disable encoding
        self.headers.pop(b'Accept-Encoding', None)

        if len(lines[-1]) > 0:
            self.data = lines[-1]

        self.integrity = True


    def __str__(self):
        parts = []
        try:
            #parts.append('Connection to %s:%d' % (self.host.decode(), self.port))
            parts.append('%s %s %s' % (self.method.decode(), self.path.decode(), self.version.decode()))
            parts += ['%s: %s' % (k.decode(), v.decode()) for k, v in self.headers.items()]
            parts.append(self.data.decode())
        except Exception as e:
            log.warn('Response encoding problem occured: '+str(e))
        return '\n'.join(parts)

    def bytes(self):
        result = b'%s %s %s\r\n' % (self.method, self.path, self.version)
        result += b'\r\n'.join([b'%s: %s' % (k, v) for k, v in self.headers.items()])
        result += b'\r\n\r\n'
        if len(self.data)>0:
            result += self.data
        return result









class Response():
    def __init__(self, data):
        self.original = data
        lines = data.splitlines()
        self.version = lines[0].partition(b' ')[0]
        self.statuscode = int(lines[0].split(b' ')[1])
        self.status = b' '.join(lines[0].split(b' ')[2:])
        self.headers = OrderedDict()

        # TODO HTTP response splitting support
        for line_index in range(1, len(lines)):
            line = lines[line_index]
            if len(line) == 0:
                break
            k, _, v = line.partition(b':')
            self.headers[k] = v.strip()
        
        self.data = b''.join([line+b'\n' for line in lines[line_index+1:]])
        
        #if self.headers.get(b'Content-Encoding') == b'gzip':
        #    self.data = lib.gunzip(self.data)
        
        if b'Content-Length' not in self.headers.keys() and len(self.data)>0:
            log.debug_parsing('Computing Content-Length...')
            self.headers[b'Content-Length'] = b'%d' % (len(self.data))


    def __str__(self):
        #log.debug_parsing(''.join(['\\x%02x' % x for x in self.data[:10]]))
        #log.debug_parsing(''.join([('   %c' % x) if x != 0x0a else '  \\n' for x in self.data[:10] ]))
        #log.debug_parsing(''.join(['\\x%02x' % x for x in self.data[-10:]]))
        #log.debug_parsing(''.join([('   %c' % x) if x != 0x0a else '  \\n' for x in self.data[-10:] ]))
        try:
            parts = []
            parts.append('%s %s %s' % (self.version.decode(), self.statuscode, self.status.decode()))
            parts += ['%s: %s' % (k.decode(), v.decode()) for k, v in self.headers.items()]
            if b'Content-Type' in self.headers and self.headers[b'Content-Type'].startswith(b'text/'):
                parts.append('\n%s' % (self.data.decode()))
        except Exception as e:
            log.warn('Response encoding problem occured: '+str(e))
        return '\n'.join(parts)

    def bytes(self):
        #data = lib.gzip(self.data) if self.headers.get(b'Content-Encoding') == b'gzip'  else self.data
        result = b''
        result += b'%s %d %s\r\n' % (self.version, self.statuscode, self.status)
        result += b'\r\n'.join([b'%s: %s' % (k, v) for k, v in self.headers.items()])
        result += b'\r\n\r\n' + self.data + b'\r\n\r\n'
        return result



class RRDB():
    def __init__(self):
        self.rrid = 0 # last rrid
        self.rrs = {} # rrid:RR()
    
    def get_new_rrid(self): # generated in Proxy(), so it is thread-safe
        self.rrid += 1
        return self.rrid

    def add_request(rrid, request):
        self.rrs[rrid] = RR(request)

    def add_response(rrid, response):
        self.rrs[rrid].add_response(response)

    def __str__(self):
        return '' # TODO nice output

weber.rrdb = RRDB()

class RR():
    def __init__(self, request):
        self.request = request
        self.response = None

    def add_response(self, response):
        self.response = response



class Mapping():
    def __init__(self):
        self.l_r = OrderedDict() # local->remote
        self.r_l = OrderedDict() # remote->local
        self.map = {}            # bytes->URI
        self.counter = 0
        self.lock = threading.Lock()
    
    def add_init(self, remote): # add first known local
        self.init_target = URI(remote)
        local = '%s:%d' % (weber.config['proxy.host'], weber.config['proxy.port' if self.init_target.scheme == 'https' else 'proxy.port']) # scheme not included in host... TODO for all cases?
        self.add(local, remote)

    def add(self, local, remote): # add known local
        l = URI(local)
        r = URI(remote)
        self.map[l.__bytes__()] = l
        self.map[r.__bytes__()] = r
        self.l_r[l] = r
        self.r_l[r] = l

    def generate(self, remote): # generate new local
        with self.lock:
            self.counter += 1
            local = '%s/%d' % (weber.config['proxy.host'], self.counter) # TODO http scheme?
        self.l_r[local] = remote
        self.r_l[remote] = local
        
        
    def get_remote(self, key):
        result = self.l_r.get(self.map.get(key))
        return result

    def get_local(self, key):
        print('getting local for', key)
        result = self.r_l.get(self.map.get(key))
        return result
        
    def get_remote_hostport(self, key):
        key = URI(key)
        matches = [x for x in self.l_r.keys() if x.domain == key.domain and x.port == key.port]
        if len(matches)>0:
            if self.l_r[matches[0]].port not in [80, 443]:
                return ('%s:%d' % (self.l_r[matches[0]].domain, self.l_r[matches[0]].port)).encode()
            else:
                return self.l_r[matches[0]].domain.encode()
        else:
            return None

    def get_local_hostport(self, key):
        key = URI(key)
        matches = [x for x in self.r_l.keys() if x.domain == key.domain and x.port == key.port]
        if len(matches)>0:
            if self.r_l[matches[0]].port not in [80,443]:
                return ('%s:%d' % (self.r_l[matches[0]].domain, self.r_l[matches[0]].port)).encode()
            else:
                return self.r_l[matches[0]].domain.encode()
        else:
            return None

weber.mapping = Mapping()

class URI():
    def __init__(self, uri):
        self.scheme, self.user, self.password, self.domain, self.port, self.path = URI.parse(uri)

    def __str__(self):
        if len(self.user)>0 and len(self.password)>0:
            return 'URI(%s://%s:%s@%s:%d%s)' % (self.scheme, self.user, self.password, self.domain, self.port, self.path)
        else:
            return 'URI(%s://%s:%d%s)' % (self.scheme, self.domain, self.port, self.path)
	
    def __bytes__(self):
        return self.__str__().encode()

    def __repr__(self):
        return self.__str__()

    def parse(uri):
        # splits https://example.com:4443/x/y.html into scheme, user, pass, domain, port and path
        if type(uri) == bytes:
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

