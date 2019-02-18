#!/usr/bin/env python3
"""
Class for HTTP is here.
"""
import socket, traceback, errno, ssl, re, itertools, threading
from threading import Thread
from datetime import datetime
from collections import OrderedDict
from select import select

from source import weber
from source import log
from source.proxy import ProxyLib, ConnectionThread
from source.structures import URI, Server
from source.lib import *
from source.fd_debug import *

class HTTP():
    """
    HTTP class generating proper HTTP objects and holding HTTP-specific constants
    """

    scheme = 'http'
    ssl_scheme = 'https'
    port = 80
    ssl_port = 443
    
    link_tags = [
        (b'<a', b'</a>', b'href'),
        (b'<form', b'</form>', b'action'),
        (b'<frame', b'</frame>', b'src'),
        (b'<img', b'>', b'src'),
        (b'<script', b'>', b'src'),
        (b'<link', b'>', b'href'),
    ] # TODO more

    fault_injection_delimiters = tuple(' \r\n:;/&?')
    
    @staticmethod
    #def create_request(data, should_tamper, no_stopper=False, request_modifier=None):
    #    return HTTPRequest(data, should_tamper, no_stopper, request_modifier)
    def create_request(data):
        return HTTPRequest(data)
    
    @staticmethod
    #def create_response(data, should_tamper, no_stopper=False):
    #    return HTTPResponse(data, should_tamper, no_stopper)
    def create_response(data):
        return HTTPResponse(data)
    
    @staticmethod
    def request_string(req, res, colored=False):
        # response is needed for proper colors

        if True:#try:
            # TODO also from Accept:
            tamperstring = ''
            if req.tampering:
                tamperstring = '[T] '
            color = log.COLOR_NONE
            
            color = log.COLOR_NONE
            # do the coloring
            if colored:
                if not res:
                    # no response received, color by extension
                    color = get_color_from_extension(req.onlypath)
                else:
                    # response received, color by Content-Type
                    content_type = res.headers.get(b'Content-Type')
                    if content_type: # missing Content-Type will be detected in analysis
                        color = get_color_from_content_type(content_type)

            # shorten path if desired
            path = req.path.decode()
            if (positive(weber.config['overview.short_request'].value)
                    and len(path)>50):
                path = '...'+path[-47:]

            # return pretty string
            return '%s%s%s%s%s %s%s' % (log.COLOR_YELLOW, tamperstring, log.COLOR_NONE, color, req.method.decode(), path, log.COLOR_NONE)
        if False:#except:
            return log.COLOR_YELLOW+log.COLOR_NONE+log.COLOR_GREY+'...'+log.COLOR_NONE
    

    @staticmethod
    def response_string(res, colored=False, show_size=False):
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
            size_string = '' if not show_size else (' (%d B)' % len(res.data))
            return '%s%s%s%s%d %s%s%s' % (log.COLOR_YELLOW, tamperstring, log.COLOR_NONE, color, res.statuscode, res.status.decode(), size_string, log.COLOR_NONE)
        except:
            return log.COLOR_YELLOW+log.COLOR_NONE+log.COLOR_GREY+'...'+log.COLOR_NONE

weber.protocols['http'] = HTTP


class HTTPRequest():
    """
    HTTP Request class

    """
    def __init__(self, data):
        """
            data = request data (bytes)
            should_tamper = should the request be tampered? (bool)
            no_stopper = should stopper IPC be created (e.g. no for cloning for downstream)
            request_modifier = function to alter request bytes before parsing
        """
        self.tampering = False # just flag so we can filter; set in ConnectionThread
        import random
        self.random = random.random()
        """set default values"""
        self.original = data
        self.method = b''
        self.path = b''
        self.version = b''
        self.headers = OrderedDict()
        self.data = b''
        self.parameters = {}
        self.integrity = False
        """no data? return"""
        if not data:
            return
        """parse received data"""
        self.parse()

    def parse(self):
        """
        parse bytes in self.original
        """
        self.method = b''
        self.path = b''
        self.version = b''
        self.headers = OrderedDict()
        self.data = b''
        self.parameters = {}
        
        log.debug_parsing('Parsing Request:')
        log.debug_parsing(self.original)
        self.headers = OrderedDict()
        lines = self.original.splitlines()
        """parse first line, spoof request regexs"""
        line0 = ProxyLib.spoof_regex(lines[0], 
                                     weber.spoof_request_regexs.items())
        try:
            self.method, self.path, self.version = tuple(line0.split(b' '))
        except:
            log.err('Invalid first header: \'%s\'' % line0) # TODO but keep as single string and use it
            self.method = b''
            self.path = b''
            self.version = b''
            self.integrity = False
            return 
        #fd_add_comment(self.forward_stopper, 'Request (%s %s) forward stopper' % (self.method, self.path))
        """spoof request regex in headers"""
        line_counter = 1
        for line in lines[1:]:
            line_counter += 1
            if not line:
                break
            line = ProxyLib.spoof_regex(line, 
                                        weber.spoof_request_regexs.items())
            k, _, v = line.partition(b':')
            # TODO duplicit keys? warn
            self.headers[k.title()] = v.strip()
        """spoof request regex in data"""   
        data_join = b'\r\n'.join(lines[line_counter:])
        if data_join:
            self.data = ProxyLib.spoof_regex(data_join, 
                                            weber.spoof_request_regexs.items())
        """parse method (for parameters)"""
        self.parse_method()
        """end of request parsing"""
        self.integrity = True

    

    #def clone(self, should_tamper=False, no_stopper=True, request_modifier=None):
    def clone(self):
        #return HTTP.create_request(self.bytes(), should_tamper, no_stopper, request_modifier)
        return HTTP.create_request(self.bytes())

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
        # TRACE works natively
        # CONNECT works natively (?)
        # TODO more methods
    
    def compute_content_length(self):
        """

        """
        if (positive(weber.config['http.recompute_request_length'].value)
            and self.data):
            log.debug_parsing('Computing Content-Length...')
            self.headers[b'Content-Length'] = b'%d' % (len(self.data))

    def lines(self, headers=True, data=True, splitter=b'\r\n', as_string=True):
        """
        
        Args:
            headers (bool, optional) - if headers should be included
            data (bool) - if data should be included
            splitter (bytes) - type of line split (\n or \r\n)
            as_string (bool) - if result should be str (else bytes)
        Returns:
            parts (obj:list of str/bytes) - list of lines
        """
        parts = []
        if headers:
            """add first line and headers"""
            parts.append(b'%s %s %s' % (self.method, self.path, self.version))
            parts += [b'%s: %s' % (k, (v if v else b''))
                      for k,v in self.headers.items()]
            """add header-data newline"""
            if data:
                parts.append(b'')
        if data:
            """test if data is to be printed and cannot"""
            if as_string:
                try:
                    _ = self.data.decode() # TODO not tested (e.g. ocsp.digicert.com)
                    parts += self.data.split(splitter)
                except:
                    parts.append(b'--- BINARY DATA ---')
                    
            else:
                """add data"""
                parts += self.data.split(splitter)
        try:
            """turn to str if desired"""
            parts = [x.decode() for x in parts] if as_string else parts
        except Exception as e:
            log.warn('Request encoding problem occured (as_string): '+str(e))
            print(parts)
            parts = []
        return parts
        

    def __str__(self):
        """
        For user printing
        """
        return '\n'.join(self.lines(splitter=b'\n'))

    def bytes(self, headers=True, data=True):
        """
        for data sending
        """
        return b'\r\n'.join(self.lines(headers,
                                       data,
                                       splitter=b'\r\n', 
                                       as_string=False))
        # TODO is that a good replacement for: ?
        '''
        result = b''
        if headers:
            result += b'%s %s %s\r\n' % (self.method, self.path, self.version)
            result += b'\r\n'.join([b'%s: %s' % (k, b'' if v is None else v) for k, v in self.headers.items()])
            result += b'\r\n\r\n'
        if data and len(self.data)>0:
            result += self.data
        return result
        '''

    def pre_tamper(self):
        """
        Things that must be done before the request can be tampered by
        Weber user.

        NOTE: request_regexs have spoofed in parse() method already.
        """
        log.debug_tampering('Running pre_tamper for the request.')
        '''
        """not connect -> remove server from req path"""
        print('removing server from req path (%f)' % self.random)
        print('before', self.path)
        self.path = self.path[
            self.path.find(b'/', self.path.find(b'/')+2):]
        print('after', self.path)
        '''
        """remove undesired headers"""
        log.debug_flow('Attempting to remove undesired headers.')
        undesired = weber.config['http.drop_request_headers'].value.encode()
        for u in undesired.split(b' '):
            try:
                del self.headers[u]
            except:
                pass
        """remove cache headers if not desired"""
        if positive(weber.config['http.no_cache'].value):
            log.debug_flow('Attempting to remove cache headers.')
            undesired = (
                b'If-Modified-Since',
                b'If-None-Match',
            )
            for u in undesired:
                try:
                    del self.headers[u]
                except:
                    pass
        """end of request pre_tamper method"""
        self.tampering = True
        log.debug_tampering('Request is ready for tamper.')

    def post_tamper(self):
        """

        """
        self.tampering = False
        log.debug_tampering('Running post_tamper for the request.')
        """compute Content-Length"""
        log.debug_flow('Attempting to re-compute Content-Length.')
        self.compute_content_length()
        """end of request post_tamper method"""
        log.debug_tampering('Request is ready for forward.')









class HTTPResponse():
    """

    """
    #def __init__(self, data, should_tamper, no_stopper=False):
    def __init__(self, data):
        """

        """
        '''
        # set up tampering mechanism
        self.should_tamper = should_tamper
        self.forward_stopper = None if no_stopper else os.pipe()
        self.tampering = should_tamper
        '''
        self.original = data
        self.status = b''
        self.statuscode = 0
        self.version = b''
        self.headers = OrderedDict()
        self.data = b''
        self.encodings = [] # TODO also in requests?
        # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
        """parse data"""
        self.parse()

        
        # allow forwarding?
        #if not self.should_tamper:
        #    self.forward()
    
    '''@staticmethod
    def spoof_regex(data):
        for old, new in weber.spoof_regexs.items():
            data = re.sub(old.encode(), new.encode(), data)
        return data
    '''
    def parse(self):
        """
        parse bytes in self.original
        """
        self.status = b''
        self.statuscode = 0
        self.version = b''
        self.headers = OrderedDict()
        self.data = b''
        self.encodings = [] # TODO also in requests?
        
        # TODO how about multipart?
        log.debug_parsing('Parsing Response:')
        log.debug_parsing(self.original)
        lines = self.original.split(b'\r\n')
        """parse first line, spoof response regexs"""
        line0 = ProxyLib.spoof_regex(lines[0], 
                                     weber.spoof_response_regexs.items())
        self.version = line0.partition(b' ')[0]
        try:
            self.statuscode = int(line0.split(b' ')[1])
        except:
            log.warn('Non-integer status code received.')
            self.statuscode = 0
        self.status = b' '.join(line0.split(b' ')[2:])
        #fd_add_comment(self.forward_stopper, 'Response (%d %s) forward stopper' % (self.statuscode, self.status))
        """parse headers, spoof response regexs"""
        line_index = 1
        for line_index in range(1, len(lines)):
            line = ProxyLib.spoof_regex(lines[line_index], 
                                        weber.spoof_response_regexs.items())
            if not line:
                break
            k, _, v = line.partition(b':')
            self.headers[k.title()] = v.strip()
        
        line_index += 1
        """determine used encodings"""
        try:
            self.encodings = (
                self.headers[b'Content-Encoding'].decode().split(', '))
        except:
            pass
        """parse data, unchunk if needed, decode if needed, 
           spoof response regexs"""
        data_line_index = line_index # backup the value
        """first unchunk"""
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
                        log.debug_chunks('end of chunk near %s' 
                                         % str(lines[line_index][-30:]))
                        line_index += 1
                        break
                    if len(tmpchunk) > chunksize: # problem...
                        log.warn('Loaded chunk bigger than advertised: %d > %d'
                                 % (len(tmpchunk), chunksize))
                        break
                    # chunk spans multiple lines...
                    tmpchunk += b'\r\n'
                #self.data += ProxyLib.spoof_regex(tmpchunk, 
                #                                  weber.spoof_response_regexs.items())
                # rather spoof after chunking? # TODO test
                self.data += tmpchunk
        except Exception as e:
            line_index = data_line_index # restore the value
            log.debug_chunks('unchunking failed:')
            log.debug_chunks(e)
            #traceback.print_exc()
            log.debug_chunks('treating as non-chunked...')
            # treat as normal data
            self.data = b'\r\n'.join(lines[line_index:]) 
        """unchunked; decode"""
        for encoding in self.encodings[::-1]: # TODO correct order, right?
            log.debug_parsing('Decoding %s' % encoding)
            self.data = decode_data(self.data, encoding) 
        """decoded; spoof regex"""
        self.data = ProxyLib.spoof_regex(
                        self.data,
                        weber.spoof_response_regexs.items())
            # TODO test for matching Content-Type (HTTP Response-Splitting etc.)
        
    
    def sanitize(self):
        """
        # alter the Response so we don't have to deal with problematic options, e.g. chunked
        # should NOT be used on the original (upstream) Response
        """
        
        # strip Transfer-Encoding...
        #self.headers.pop(b'Transfer-Encoding', None)
        
        # no wild upgrading (HTTP/2)
        #self.headers.pop(b'Upgrade', None)


    #def clone(self, should_tamper=True, no_stopper=True):
    #    return HTTP.create_response(self.bytes(), should_tamper, no_stopper)
    def clone(self):
        return HTTP.create_response(self.bytes())

    def compute_content_length(self): # TODO also with option?
        #if b'Content-Length' not in self.headers.keys() and len(self.data)>0:
        if self.data: # TODO added; test it
            log.debug_parsing('Computing Content-Length...')
            self.headers[b'Content-Length'] = b'%d' % (len(self.data))

    def lines(
            self, 
            headers=True, 
            data=True, 
            splitter=b'\r\n', 
            as_string=True, 
            encode=False):
        """
        
        Args:
            headers (bool, optional) - if headers should be included
            data (bool) - if data should be included
            splitter (bytes) - type of line split (\n or \r\n)
            as_string (bool) - if result should be str (else bytes)
            encoded (bool) - if Content-Encoding should be used
        Returns:
            parts (obj:list of str/bytes) - list of lines
        """
        parts = []
        """first deal with encoding (so Content-Length is OK)"""
        data_encoded = self.data
        #print('encoding', '' if encode else 'NOT', 'desired')
        #print('encodings:', self.encodings)
        if encode:
            for encoding in self.encodings: # TODO correct order, right?
                log.debug_parsing('Encoding to %s' % encoding)
                data_encoded = encode_data(data_encoded, encoding)
        
        if headers:
            """add first line and headers"""
            self.compute_content_length()
            parts.append(b'%s %d %s' % 
                         (self.version, self.statuscode, self.status))
            parts += [b'%s: %s' % (k, ((v or '') 
                                       if k != b'Content-Length' 
                                       else b'%d' % len(data_encoded)))
                      for k, v in self.headers.items()]
            """add header-data newline"""
            if data:
                parts.append(b'')
        if data:
            """add data"""
            """not if binary and as_string is wanted"""
            if as_string and self.statuscode < 300 and not \
                    is_content_type_text(self.headers.get(b'Content-Type')):
                parts.append(b'--- BINARY DATA ---')
            else:
                parts += data_encoded.split(splitter)
        try:
            parts = [x.decode('utf-8', 'replace') 
                     for x in parts] if as_string else parts # not accurate # TODO needed?
        except Exception as e:
            log.warn('Response encoding problem occured: %s' % (str(e)))
            log.warn('For '+str(self.headers))
            parts = []
        return parts

    def __str__(self):
        """
        For user printing
        """
        return '\n'.join(self.lines(splitter=b'\n'))

    def bytes(self, headers=True, data=True, encode=False):
        """
        for data sending and storage 
        """
        return b'\r\n'.join(self.lines(headers, 
                                       data, 
                                       splitter=b'\r\n', 
                                       as_string=False,
                                       encode=encode))
    '''
    def __str__(self):
        return '\n'.join(self.lines())
    def bytes(self, headers=True, data=True):
        self.compute_content_length()
        #data = lib.gzip(self.data) if self.headers.get(b'Content-Encoding') == b'gzip'  else self.data
        result = b''
        if headers:
            result += b'%s %d %s\r\n' % (self.version, self.statuscode, self.status)
            result += b'\r\n'.join([b'%s: %s' % (k, b'' if v is None else v) for k, v in self.headers.items()])
        if data:
            result += b'\r\n\r\n' + self.data 
        result += b'\r\n\r\n'
        return result
    '''
    def pre_tamper(self):
        """
        Things that must be done before the response can be tampered by
        Weber user.

        NOTE: response_regexs have been spoofed in parse() method.
        """
        log.debug_tampering('Running pre_tamper for the response.')
        self.sanitize()
        """Drop Transfer-Encoding header"""
        if self.headers.get(b'Transfer-Encoding') == b'chunked':
            log.debug_flow('Dropping Transfer-Encoding header.')
            del self.headers[b'Transfer-Encoding']
        """remove undesired headers"""
        log.debug_flow('Attempting to remove undesired headers.')
        undesired = weber.config['http.drop_response_headers'].value.encode()
        for u in undesired.split(b' '):
            try:
                del self.headers[u]
            except:
                pass
        """remove cache headers if not desired"""
        if positive(weber.config['http.no_cache'].value):
            log.debug_flow('Attempting to remove cache headers.')
            for undesired in (b'Expires',):
                try:
                    del self.headers[undesired]
                except:
                    pass
            self.headers[b'Cache-Control'] = (b'no-cache, no-store, '
                                             b'must-revalidate')
            self.headers[b'Pragma'] = b'no-cache'
        ''' IN ConnectionThread
        # store response data if desired
        if weber.config['crawl.save_path'].value:
            if response.statuscode >= 200 and response.statuscode < 300:
                # TODO what about custom error pages? but probably not...
                # TODO test content-length and 0 -> directory? 
                log.debug_flow('Saving response data into file.')
                file_path = create_folders_from_uri(
                                weber.config['crawl.save_path'].value,
                                self.remoteuri)
                with open(file_path, 'wb') as f:
                    f.write(b'\n'.join(response.lines(headers=False, as_string=False)))
        """end of response pre_tamper method"""
        '''
        self.tampering = True
        log.debug_tampering('Response is ready for tamper.')

    def post_tamper(self, full_uri):
        """

        """
        self.tampering = False
        log.debug_tampering('Running post_tamper for the response.')
        """spoof files if desired (with or without GET arguments)"""
        log.debug_flow('Spoofing files.')
        spoof_path = (full_uri.tostring() 
                      if positive(weber.config['spoof.arguments'].value) 
                      else full_uri.tostring().partition('?')[0])
        if spoof_path in weber.spoof_files.keys():
            self.spoof(weber.spoof_files[spoof_path])
        """end of response post_tamper method"""
        log.debug_tampering('Response is ready for forward.')
    

    def find_html_attr(self, tagstart, tagend, attr):
        """
        This method uses find_between() method to locate attributes 
        and their values for specified tag.

        Returns:
            list of (absolute_position, match_string) of attributes
        """
        """find matches with context"""
        tagmatches = find_between(self.data, tagstart, tagend)
        result = []
        for pos, _ in tagmatches:
            """find the end of the tagstart"""
            endpos = self.data.index(b'>', pos)
            """find value between 'attr="' and '"' """
            linkmatches = find_between(self.data, 
                                       b'%s="' % (attr), 
                                       b'"', 
                                       startpos=pos, 
                                       endpos=endpos, 
                                       inner=True)
            # TODO what if "'s are not used?
            #   in context -> maybe just find attr occurence in tag...
            result += linkmatches
        return result
    '''
    def replace_links(self, tagstart, tagend, attr, prepend=b''):
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
        #connect_paths = lambda x,y: x+(b'/' if not x.endswith(b'/') and not y.startswith(b'/') else b'')+(y[1:] if x.endswith(b'/') and y.startswith(b'/') else y)
        newparts = [b'%s="%s"' % (attr, (prepend+(b'' if x[1].startswith(b'/') else b'/')+x[1] if not x[1].partition(b'://')[0] in (b'http', b'https') else weber.mapping.get_local(x[1]))) for x in linkmatches]
        # join oldparts and newparts
        result = filter(None, [x for x in itertools.chain.from_iterable(itertools.zip_longest(oldparts, newparts))])
        self.data = b''.join(result)
    '''
    
    def find_tags(self, startends, attrs=None, valueonly=False):
        result = []
        if not attrs or not valueonly:
            """no href and other attributes OR with context; 
            just simple find_between"""
            for startbytes, endbytes in startends:
                result += [x[1].decode() 
                           for x in find_between(self.data, 
                                                 startbytes, 
                                                 endbytes, 
                                                 inner=valueonly)]
        else:
            """get value from specific attribute"""
            for (startbytes, endbytes), attr in zip(startends, attrs):
                result += [x[1].decode() 
                           for x in self.find_html_attr(startbytes, 
                                                        endbytes, 
                                                        attr)]
        return result


    def spoof(self, path):
        """
        replace data with file content
        """
        try:
            with open(path, 'rb') as f:
                self.data = f.read()
            self.statuscode = 200
            self.status = b'OK'
            self.compute_content_length()
        except:
            log.err('Spoofing failed - cannot open file.')



