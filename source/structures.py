#!/usr/bin/env python3
"""
Various structures are defined here.
"""
from source import weber
from source import log
from source import lib

import codecs, threading, xmltodict
from collections import OrderedDict


class Request():
    def __init__(self, data):
        self.integrity = False
        if len(data) == 0:
            return
        self.original = data
        lines = data.splitlines()
        self.method, self.path, self.version = tuple(lines[0].split(b' '))
        self.parameters = {}
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

        # GET method
        if self.method in [b'GET']:
            self.realpath, _, tmpparams = self.path.partition(b'?')
            for param in tmpparams.split(b'&'):
                if param == b'':
                    continue
                try:
                    k, v = tuple(param.split(b'='))
                    self.parameters[k] = v
                except:
                    log.debug_parsing('Cannot parse GET arguments properly:\'%s\'' % (param))
                    continue
        
        #TODO POST

        # TODO HEAD

        self.integrity = True

    def lines(self, headers=True, data=True):
        parts = []
        try:
            #parts.append('Connection to %s:%d' % (self.host.decode(), self.port))
            if headers:
                parts.append('%s %s %s' % (self.method.decode(), self.path.decode(), self.version.decode()))
                parts += ['%s: %s' % (k.decode(), v.decode()) for k, v in self.headers.items()]
            if data:
                parts.append(self.data.decode())
        except Exception as e:
            log.warn('Response encoding problem occured: '+str(e))
        return parts

    def __str__(self):
        return '\n'.join(self.lines())

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
        
        # TODO splitlines for grep? if text/*
        # TODO Transfer-Encoding: chunked # even when the header is missing
            
        self.data = b''.join([line+b'\n' for line in lines[line_index+1:]])

        # try to parse xml
        self.dict = {}
        if self.headers.get(b'Content-Type').startswith(b'text/html'):
            try:
                self.dict = xmltodict.parse(self.data)
            except Exception as e:
                print(e)
        #if self.headers.get(b'Content-Encoding') == b'gzip':
        #    self.data = lib.gunzip(self.data)
        
        if b'Content-Length' not in self.headers.keys() and len(self.data)>0:
            log.debug_parsing('Computing Content-Length...')
            self.headers[b'Content-Length'] = b'%d' % (len(self.data))


    def lines(self, headers=True, data=True):
        parts = []
        #log.debug_parsing(''.join(['\\x%02x' % x for x in self.data[:10]]))
        #log.debug_parsing(''.join([('   %c' % x) if x != 0x0a else '  \\n' for x in self.data[:10] ]))
        #log.debug_parsing(''.join(['\\x%02x' % x for x in self.data[-10:]]))
        #log.debug_parsing(''.join([('   %c' % x) if x != 0x0a else '  \\n' for x in self.data[-10:] ]))
        try:
            if headers:
                parts.append('%s %s %s' % (self.version.decode(), self.statuscode, self.status.decode()))
                parts += ['%s: %s' % (k.decode(), v.decode()) for k, v in self.headers.items()]
            if data:
                # TODO what exactly?
                if b'Content-Type' in self.headers and self.headers[b'Content-Type'].startswith((b'text/', b'application/')):
                    parts.append('\n%s' % (self.data.decode()))
        except Exception as e:
            log.warn('Response encoding problem occured: '+str(e))
        return parts

    def __str__(self):
        return '\n'.join(self.lines())

    def bytes(self):
        #data = lib.gzip(self.data) if self.headers.get(b'Content-Encoding') == b'gzip'  else self.data
        result = b''
        result += b'%s %d %s\r\n' % (self.version, self.statuscode, self.status)
        result += b'\r\n'.join([b'%s: %s' % (k, v) for k, v in self.headers.items()])
        result += b'\r\n\r\n' + self.data + b'\r\n\r\n'
        return result

    def get_tags_recursive(tagname, d):
       # generate desired tags
        if tagname in d.keys():
            yield d[tagname]
        for v in d.values():
            if isinstance(v, dict):
                for x in Response.get_tags_recursive(tagname, d=v):
                    yield x
    
    def find_tags(self, tagname, form='dict'):
        if len(self.dict.items())<=0:
            print('dict empty!')
        return list(Response.get_tags_recursive(tagname, self.dict))
"""
Database of Request/Response pairs.
"""
class RRDB():
    def __init__(self):
        self.rrid = 0 # last rrid
        self.rrs = OrderedDict() # rrid:RR()
    
    def get_new_rrid(self): # generated in Proxy(), so it is thread-safe
        self.rrid += 1
        return self.rrid

    def add_request(self, rrid, request):
        self.rrs[rrid] = RR(request)

    def add_response(self, rrid, response):
        self.rrs[rrid].add_response(response)

    def get_desired_rrs(self, args):
        if len(self.rrs.keys()) == 0:
            return {}
        indices = []
        minimum = 1
        maximum = max(self.rrs.keys())
        if len(args) == 1:
            for desired in args[0].split(','):
                start = minimum
                end = maximum
                
                if ':' in desired:
                    _start, _, _end = desired.partition(':')                    
                else:
                    _start = _end = desired
                if _start.isdigit():
                    start = max([start, int(_start)])
                if _end.isdigit():
                    end = min([end, int(_end)])
                if start > end:
                    tmp = start
                    start = end
                    end = tmp
                indices += list(range(start, end+1))
        else:
            indices = range(minimum, maximum+1)

        return {i: self.rrs[i] for i in sorted(indices) if i in self.rrs.keys()}

    
    def overview(self, args, header=True):
        result = []
        reqlen = max([20]+[1+len(v.request_string(short=True, colored=True)) for v in self.get_desired_rrs(args).values()])
        
        if header:
            hreqlen = reqlen-len(log.COLOR_GREEN)-len(log.COLOR_NONE)
            log.tprint('    EID  RRID  %-*s  Response' % (hreqlen, 'Request'))
            log.tprint('    ===  ====  %-*s  ====================' % (hreqlen, '='*hreqlen))
       
        for rrid, rr in self.get_desired_rrs(args).items():
            result.append('    %-3s  %-4d  %-*s  %-20s' % ('', rrid, reqlen, rr.request_string(short=True, colored=True), rr.response_string(short=True, colored=True))) # TODO EID
        return result

            

weber.rrdb = RRDB()

"""
Request/Response pair
"""
class RR():
    def __init__(self, request):
        self.request = request
        self.response = None

    def add_response(self, response):
        self.response = response

    def request_string(self, short=False, colored=False):
        if True: #try:
            if short:
                # TODO also from Accept:
                color = log.COLOR_NONE
                if self.request.realpath == b'/' or self.request.realpath.endswith((b'.htm', b'.html', b'.php', b'.xhtml', b'.aspx')):
                    color = log.COLOR_GREY
                elif self.request.realpath.endswith((b'.jpg', b'.svg', b'.png', b'.gif', b'.ico', b'.mp3', b'.ogg', b'.mp4', b'.wav')):
                    color = log.COLOR_PURPLE
                elif self.request.realpath.endswith((b'.js', b'.vbs', b'.swf')):
                    color = log.COLOR_BLUE
                elif self.request.realpath.endswith((b'.css')):
                    color = log.COLOR_DARK_PURPLE
                elif self.request.realpath.endswith((b'.pdf', b'.doc', b'.docx', b'.xls', b'.xlsx', b'.ppt', b'.pptx', b'.pps', b'.ppsx', b'.txt')):
                    color = log.COLOR_GREEN
                elif self.request.realpath.endswith((b'.zip', b'.7z', b'.rar', b'.gz', b'.bz2', b'.jar', b'.bin', b'.iso')):
                    color = log.COLOR_BROWN
                if not colored:
                    color = log.COLOR_NONE
                return '%s%s %s%s' % (color, self.request.method.decode(), self.request.path.decode(), log.COLOR_NONE)
        # TODO long
        if False: #except:
            return log.COLOR_GREY+'...'+log.COLOR_NONE

    def response_string(self, short=False, colored=False):
        try:
            if short:
                if self.response.statuscode < 200:
                    color = log.COLOR_NONE
                elif self.response.statuscode == 200:
                    color = log.COLOR_DARK_GREEN
                elif self.response.statuscode < 300:
                    color = log.COLOR_GREEN
                elif self.response.statuscode < 400:
                    color = log.COLOR_BROWN
                elif self.response.statuscode < 500:
                    color = log.COLOR_DARK_RED
                elif self.response.statuscode < 600:
                    color = log.COLOR_DARK_PURPLE
                else:
                    color = log.COLOR_NONE
                if not colored:
                    color = log.COLOR_NONE
                
                return '%s%d %s%s' % (color, self.response.statuscode, self.response.status.decode(), log.COLOR_NONE)
            # TODO long
        except:
            return log.COLOR_GREY+'...'+log.COLOR_NONE
        

"""
Local-Remote URI mapping
"""
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
            if self.r_l[matches[0]].port not in [80, 443]:
                return ('%s:%d' % (self.r_l[matches[0]].domain, self.r_l[matches[0]].port)).encode()
            else:
                return self.r_l[matches[0]].domain.encode()
        else:
            return None

weber.mapping = Mapping()

"""
Single URI
"""
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

