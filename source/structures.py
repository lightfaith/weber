#!/usr/bin/env python3
"""
Various structures are defined here.
"""
import threading, traceback
from collections import OrderedDict
from bs4 import BeautifulSoup as soup

from source import weber
from source import log
from source.lib import *


class Request():
    """
    HTTP Request class
    """
    def __init__(self, data):
        self.integrity = False
        if not data:
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
            if not line:
                continue
            k, _, v = line.partition(b':')
            # TODO duplicit keys? warn
            self.headers[k] = v.strip()
            
        # disable encoding
        self.headers.pop(b'Accept-Encoding', None)
        # disable Range
        self.headers.pop(b'Range', None)
        self.headers.pop(b'If_Range', None)

        if len(lines[-1]) > 0:
            self.data = lines[-1]

        self.parse_method()
        self.integrity = True

    def parse_method(self):
        # GET method
        if self.method in [b'GET', b'HEAD']:
            self.realpath, _, tmpparams = self.path.partition(b'?')
            for param in tmpparams.split(b'&'):
                if param == b'':
                    continue
                k, _, v = tuple(param.partition(b'='))
                v = None if v == b'' else v
                self.parameters[k] = v
        # POST method
        if self.method in [b'POST']:
            self.realpath, _, _ = self.path.partition(b'?')
            for param in self.data.split(b'&'):
                if param == b'':
                    continue
                k, _, v = param.partition(b'=')
                v = None if v == b'' else v
                self.parameters[k] = v
        # TODO more methods


    def lines(self, headers=True, data=True):
        parts = []
        try:
            #parts.append('Connection to %s:%d' % (self.host.decode(), self.port))
            if headers:
                parts.append('%s %s %s' % (self.method.decode(), self.path.decode(), self.version.decode()))
                parts += ['%s: %s' % (k.decode(), '' if v is None else v.decode()) for k, v in self.headers.items()]
                if data:
                    parts.append('')
            if data:
                parts += self.data.decode().split('\n')
        except Exception as e:
            log.warn('Response encoding problem occured: '+str(e))
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
    link_tags = [('a', 'href', None), ('form', 'action', None), ('frame', 'src', None), ('img', 'src', None), (  'script', 'src', None)] # TODO more?

    def __init__(self, data):
        self.original = data
        lines = data.split(b'\r\n')
        self.version = lines[0].partition(b' ')[0]
        self.statuscode = int(lines[0].split(b' ')[1])
        self.status = b' '.join(lines[0].split(b' ')[2:])
        self.headers = OrderedDict()
        self.soup = None

        # load first set of headers (hopefully only one)
        line_index = 1
        for line_index in range(1, len(lines)):
            line = lines[line_index]
            if len(line) == 0:
                break
            k, _, v = line.partition(b':')
            self.headers[k] = v.strip()
        
        # TODO splitlines for grep? if text/*
        line_index += 1

        # chunked Transfer-Encoding? TODO no busy-waiting
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
        
        # strip Transfer-Encoding...
        self.headers.pop(b'Transfer-Encoding', None)
        
        # no wild upgrading (HTTP/2)
        self.headers.pop(b'Upgrade', None)

        #self.data = b''.join([line+b'\n' for line in lines[line_index+1:]])
        """
        # try to parse xml
        self.dict = {}
        if b'Content-Type' in self.headers:
            if self.headers[b'Content-Type'].startswith(b'text/html'):
                try:
                    # doctype causes trouble...
                    xmldata = b'\n'.join(self.data.split(b'\n')[1:]) if self.data.startswith(b'<!DOCTYPE') else self.data
                    self.dict = xmltodict.parse(xmldata)
                    # TODO bugged html is not parsed correctly!
                except Exception as e:
                    log.err('XMLtoDict Exception:'+str(e))
                    print(xmldata)
        #if self.headers.get(b'Content-Encoding') == b'gzip':
        #    self.data = lib.gunzip(self.data)
        """
        if b'Content-Type' not in self.headers or self.headers[b'Content-Type'].startswith(b'text/html'):
            self.soup = soup(self.data.replace(b'<!--', b'<comment>').replace(b'-->', b'</comment>'), "lxml") # TODO this is madness
        #print(self.soup.prettify())
 
    def compute_content_length(self):
        #if b'Content-Length' not in self.headers.keys() and len(self.data)>0:
        log.debug_parsing('Computing Content-Length...')
        data = self.data if self.soup is None else str(self.soup).encode('utf8')
        self.headers[b'Content-Length'] = b'%d' % (len(data))

    def lines(self, headers=True, data=True):
        parts = []
        #log.debug_parsing(''.join(['\\x%02x' % x for x in self.data[:10]]))
        #log.debug_parsing(''.join([('   %c' % x) if x != 0x0a else '  \\n' for x in self.data[:10] ]))
        #log.debug_parsing(''.join(['\\x%02x' % x for x in self.data[-10:]]))
        #log.debug_parsing(''.join([('   %c' % x) if x != 0x0a else '  \\n' for x in self.data[-10:] ]))
        try:
            if headers:
                self.compute_content_length()
                parts.append('%s %s %s' % (self.version.decode(), self.statuscode, self.status.decode()))
                parts += ['%s: %s' % (k.decode(), '' if v is None else v.decode()) for k, v in self.headers.items()]
                if data:
                    parts.append('')
            if data:
                # TODO what exactly?
                if b'Content-Type' in self.headers and self.headers[b'Content-Type'].startswith((b'text/', b'application/')):
                    #parts.append('\n%s' % (self.data.decode()))
                    parts += self.data.decode().split('\n')
        except Exception as e:
            log.warn('Response encoding problem occured: '+str(e))
        return parts

    def __str__(self):
        return '\n'.join(self.lines())

    def bytes(self):
        self.compute_content_length()
        #data = lib.gzip(self.data) if self.headers.get(b'Content-Encoding') == b'gzip'  else self.data
        result = b''
        result += b'%s %d %s\r\n' % (self.version, self.statuscode, self.status)
        result += b'\r\n'.join([b'%s: %s' % (k, b'' if v is None else v) for k, v in self.headers.items()])
        
        if self.soup is None:
            data = self.data
        else:
            data = str(self.soup).encode('utf8')
        result += b'\r\n\r\n' + data + b'\r\n\r\n'
        return result
    """
    def get_tags_recursive(tagname, d):
       # generate desired tags
        if tagname in d.keys():
            yield d[tagname]
        for v in d.values():
            if isinstance(v, dict):
                for x in Response.get_tags_recursive(tagname, d=v):
                    yield x
    """ 
    def find_tags(self, tagname, attr_key=None, attr_value=None, form='soup'):
        """
            Supported forms:
                soup - beautifulsoup object
                xml - xml as string
                value - desired value as string
        """
        if self.soup is None:
            return []

        if attr_key is not None:
            if attr_value is not None: # attribute value condition?
                #result = soup.find_all(tagname, {attr_key: attr_value})
                result = list(filter(None, [(x[attr_key] if form=='value' else x) for x in self.soup.find_all(tagname, {attr_key: attr_value})]))
            else: # attribute name condition?
                result = list(filter(None, [(x[attr_key] if form=='value' else x) for x in self.soup.find_all(tagname) if x.has_attr(attr_key)]))
                #result = [x for x in self.soup.find_all(tagname) if attr_key in x]
        else: # no conditions
            result = list(filter(None, [(x.string if form=='value' else x) for x in self.soup.find_all(tagname)]))
        if form == 'soup':
            return list(result)
        elif form in ['xml', 'value']:
            return [str(x) for x in result]
        """if len(self.dict.items())<=0:
            print('dict empty!')
        return list(Response.get_tags_recursive(tagname, self.dict))
        """
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

    def get_desired_rrs(self, arg):
        if len(self.rrs.keys()) == 0:
            return {}
        indices = []
        minimum = 1
        maximum = max(self.rrs.keys())
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
        arg = None if len(args)<1 else args[0]
        eidlen = max([3]+[len(str(e)) for e,_ in weber.events.values()])
        reqlen = max([20]+[1+len(v.request_string(short=True, colored=True)) for v in self.get_desired_rrs(arg).values()])
        
        # TODO size, time if desired
        if header:
            hreqlen = reqlen-len(log.COLOR_GREEN)-len(log.COLOR_NONE)
            log.tprint('    %-*s  RRID  %-*s  Response' % (eidlen, 'EID', hreqlen, 'Request'))
            log.tprint('    %s  ====  %-*s  ====================' % ('='*eidlen, hreqlen, '='*hreqlen))
       
        for rrid, rr in self.get_desired_rrs(arg).items():
            result.append('    %-*s  %-4d  %-*s  %-20s' % (eidlen, '' if rr.eid is None else rr.eid, rrid, reqlen, rr.request_string(short=True, colored=True), rr.response_string(short=True, colored=True)))
        return result

            

weber.rrdb = RRDB()

"""
Request/Response pair
"""
class RR():
    def __init__(self, request):
        self.request = request
        self.response = None
        self.eid = None

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
        self.init_target = None
    
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
        return (l, r)

    def generate(self, remote, scheme): # generate new local
        with self.lock:
            self.counter += 1
            port = weber.config['proxy.port' if scheme == 'http' else 'proxy.sslport']
            local = '%s://%s:%d/WEBER-MAPPING/%d' % (scheme, weber.config['proxy.host'], port, self.counter) 
        return self.add(local, remote)
        
        
    def get_remote(self, key):
        result = self.l_r.get(self.map.get(key))
        return result

    def get_local(self, key):
        print(self.r_l)
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
    
    def get_local_uri_from_hostport_path(self, hostport, path):
        host, _, port = hostport.decode().partition(':')
        port = int(port)
        path = path.decode()
        scheme = 'https' if port == weber.config['proxy.sslport'] else 'http'
        #print(scheme, type(scheme), host, type(host), port, type(port), path, type(path))
        for uri, _ in self.l_r.items():
            #print('comparing to: ', uri.scheme, type(uri.scheme), uri.domain, type(uri.domain), uri.port, type(uri.port), uri.path, type(uri.path) )
            if uri.scheme == scheme and uri.domain == host and uri.port == port and uri.path == path:
                return uri
        return None

weber.mapping = Mapping()

"""
Single URI
"""
class URI():
    def __init__(self, uri):
        self.scheme, self.user, self.password, self.domain, self.port, self.path = URI.parse(uri)

    def get_value(self):
        if len(self.user)>0 and len(self.password)>0:
            return '%s://%s:%s@%s:%d%s' % (self.scheme, self.user, self.password, self.domain, self.port, self.path)
        else:
            return '%s://%s:%d%s' % (self.scheme, self.domain, self.port, self.path)
        
    def __str__(self):
            return 'URI(%s)' % (self.get_value()) 
	
    def __bytes__(self):
        return self.__str__().encode()

    def __repr__(self):
        return self.__str__()

    @staticmethod
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

"""
Event
"""
class Event():
    def __init__(self, eid):
        self.eid = eid
        self.rrids = set()
        self.type = ''

    
