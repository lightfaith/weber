#!/usr/bin/env python3
"""
Class for HTTP is here.
"""
import socket, traceback, errno, ssl, re, itertools, threading
from threading import Thread
from collections import OrderedDict
from select import select

from source import weber
from source import log
from source.proxy import ProxyLib, ConnectionThread
from source.structures import URI
from source.lib import *
from source.fd_debug import *


log.info('  PTTP')
class PTTP():
    """
    PTTP class for multiple-protocol-support testing
    """

    scheme = 'pttp'
    ssl_scheme = 'pttps'
    port = 81
    ssl_port = 444

    link_tags = [] 
    fault_injection_delimiters = tuple()

    @staticmethod
    def create_connection_thread(conn, rrid, tamper_request, tamper_response, template_rr=None, brute_set=None):
        return PTTPConnectionThread(conn, rrid, tamper_request, tamper_response, template_rr, brute_set)

    @staticmethod
    def create_request(data, should_tamper, no_stopper=False):
        return PTTPRequest(data, should_tamper, no_stopper)
    
    @staticmethod
    def create_response(data, should_tamper, no_stopper=False):
        return PTTPResponse(data, should_tamper, no_stopper)
    
    @staticmethod
    def request_string(req, res, colored=False):
        # response is needed for proper colors

        if True:#try:
            # TODO also from Accept:
            tamperstring = ''
            if req.tampering:
                tamperstring = '[T] '
            color = log.COLOR_NONE
            
            color = log.MIMECOLOR_MULTIMEDIA

            return '%s%s%s%s%s%s' % (log.COLOR_YELLOW, tamperstring, log.COLOR_NONE, color, req.command, log.COLOR_NONE)
        if False:#except:
            return log.COLOR_YELLOW+log.COLOR_NONE+log.COLOR_GREY+'...'+log.COLOR_NONE
    

    @staticmethod
    def response_string(res, colored=False):
        try:
            tamperstring = ''
            if res.tampering:
                tamperstring = '[T] '
            color = log.COLOR_NONE
            return '%s%s%s%s%s%s' % (log.COLOR_YELLOW, tamperstring, log.COLOR_NONE, color, res.command, log.COLOR_NONE)
        except:
            return log.COLOR_YELLOW+log.COLOR_NONE+log.COLOR_GREY+'...'+log.COLOR_NONE
    

    # analysis stuff
    intra_tests = [
    ]


weber.protocols['pttp'] = PTTP




class PTTPConnectionThread(ConnectionThread):
    """
    Class for dealing with PTTP communication.
    Most stuff is done in parent generic ConnectionThread (source.proxy).
    """
    def __init__(self, conn, local_port, rrid, tamper_request, tamper_response, template_rr=None, brute_set=None):
        super().__init__(conn, local_port, rrid, tamper_request, tamper_response, template_rr, brute_set)
        self.Protocol = PTTP
        log.debug_flow('PTTP ConnectionThread created.')
        # conn - socket to browser, None if from template
        # rrid - index of request-response pair
        # tamper_request - should the request forwarding be delayed?
        # tamper_response - should the response forwarding be delayed?
        # known_rr - known request (e.g. copy of existing for bruteforcing) - don't communicate with browser if not None
        # brute_set - list of values destined for brute placeholder replacing

    
    def run(self):
        log.debug_flow('ConnectionThread started.')
        request = None
        response = None
        while self.keepalive:
            # receive request from browser / copy from template RR
            if self.template_rr is None:
                request = self.receive_request()
            else:
                request = self.template_rr.request_upstream.clone(self.tamper_request)
            
            if request is None: # socket closed? socket problem?
                log.debug_parsing('Request is broken, ignoring...') # TODO comment, 
                break
            log.debug_flow('Request of integrity received.')
            self.keepalive = False #(request.headers.get(b'Connection') == b'Keep-Alive')
            
            log.debug_flow('Getting localuri from request.')
            if self.template_rr is None:
                self.localuri = URI(URI.build_str(weber.config['proxy.host'][0], self.local_port, Protocol=PTTP))
            else:
                self.localuri = self.template_rr.uri_upstream.clone()

            # localuri had problems in the past? give up...

            if str(self.localuri) in weber.forward_fail_uris:
                break

            log.debug_mapping('request source: %s ' % (str(self.localuri)))
            log.debug_parsing('\n'+'-'*15+'\n'+str(request)+'\n'+'='*20)
            
            log.debug_flow('Saving request downstream.')
            # create request backup, move into RRDB
            request_downstream = request.clone()
            request.sanitize()
            weber.rrdb.add_request(self.rrid, request_downstream, request, PTTP)
            weber.rrdb.rrs[self.rrid].uri_downstream = self.localuri
            
            
            # change outgoing links (useless if from template)
            if self.template_rr is None:
                log.debug_flow('Changing outgoing links.')
                self.remoteuri = weber.mapping.get_remote(self.localuri)
                if self.remoteuri is None:
                    log.err('Cannot forward - local URI is not mapped. Terminating thread...')
                    weber.forward_fail_uris.append(str(self.localuri))
                    break
                log.debug_parsing('\n'+str(request)+'\n'+'#'*20)
            else:
                self.remoteuri = self.localuri.clone() # as we are working with upstream rr already
            
            weber.rrdb.rrs[self.rrid].uri_upstream = self.remoteuri
            
            log.debug_flow('Filling in brute values.')
            # change brute placeholders
            if self.brute_set is not None:
                brute_bytes = request.bytes()
                placeholder = weber.config['brute.placeholder'][0].encode()
                for i in range(len(self.brute_set)):
                    brute_bytes = brute_bytes.replace(b'%s%d%s' % (placeholder, i, placeholder), self.brute_set[i])
                request.parse(brute_bytes)


            log.debug_flow('Attempting to tamper the request.')
            # tamper request
            if request.tampering and positive(weber.config['overview.realtime'][0]):
                log.tprint('\n'.join(weber.rrdb.overview(['%d' % self.rrid], header=False)))
            r, _, _ = select([request.forward_stopper[0], self.stopper[0]], [], [])
            if self.stopper[0] in r:
                # Weber is terminating
                break

            log.debug_flow('Forwarding request.')
            # forward request to server        
            log.debug_socket('Forwarding request... (%d B)' % (len(request.command)))
            #response = self.forward(self.remoteuri, request.bytes())
            response = self.Protocol.create_response(request.command.replace('HELLO', 'I\'m awoken').replace('TIME', 'FUCK 3:15').encode(), self.tamper_response)
            log.debug_flow('Response received.')
            
            if response is None:
                weber.forward_fail_uris.append(str(self.localuri))
                break
            ###############################################################################

            log.debug_parsing('\n'+str(response)+'\n'+'='*30)
            
            # move response into RRDB
            log.debug_flow('Sanitizing response.')
            response.sanitize()
            weber.rrdb.add_response(self.rrid, response, None, allow_analysis=False)

            
            # tamper response
            log.debug_flow('Attempting to tamper the response.')
            if response.tampering and positive(weber.config['overview.realtime'][0]):
                log.tprint('\n'.join(weber.rrdb.overview(['%d' % self.rrid], header=False)))
            r, _, _ = select([response.forward_stopper[0], self.stopper[0]], [], [])
            if self.stopper[0] in r:
                # Weber is terminating
                break


            log.debug_flow('Attempting to spoof files for response.')
            # spoof files if desired (with or without GET arguments)
            spoof_path = self.remoteuri.get_value() if positive(weber.config['spoof.arguments'][0]) else self.remoteuri.get_value().partition('?')[0]
            if spoof_path in weber.spoof_files.keys():
                response.spoof(weber.spoof_files[spoof_path])


            log.debug_flow('Saving response upstream.')
            # set response as downstream, create backup (upstream), update RRDB and do the analysis
            response_upstream = response.clone()
            response_upstream.tampering = False
            weber.rrdb.add_response(self.rrid, response_upstream, response, allow_analysis=True)
            

            # send response to browser if not from template
            if self.template_rr is None:
                try:
                    self.send_response(response)
                    log.debug_flow('Response forwarded to client.')
                except socket.error as e:
                    if isinstance(e.args, tuple):
                        if e.args[0] == errno.EPIPE:
                            log.err('Connection closed for #%d, response not forwarded.' % (self.rrid))
                        else:
                            raise e
                    else:
                        raise e
                except Exception as e:
                    log.err('Failed to forward response (#%d): %s' % (self.rrid, str(e)))
                    log.err('See traceback:')
                    traceback.print_exc()

            # print if desired
            if positive(weber.config['overview.realtime'][0]):
                log.tprint('\n'.join(weber.rrdb.overview(['%d' % self.rrid], header=False)))
        
        log.debug_flow('Terminating PTTP ConnectionThread.')
        # close connection if not None (from template)
        if self.conn:
            self.conn.close()

        # close stoppers
        for r in [request, response]:
            if r:
                for fd in [0, 1]:
                    if r.forward_stopper:
                        os.close(r.forward_stopper[fd])
                r.forward_stopper = None
        for fd in [0, 1]:
            if self.stopper:
                os.close(self.stopper[fd])
        self.stopper = None
        log.debug_flow('PTTP ConnectionThread terminated.')
        




class PTTPRequest():
    """
    PTTP Request class
    """
    def __init__(self, data, should_tamper, no_stopper=False):
        """
            data = request data (bytes)
            should_tamper = should the request be tampered? (bool)
        """
        self.integrity = False
        if not data:
            return
        
        # set up tampering mechanism
        self.should_tamper = should_tamper
        #self.forward_stopper = None if no_stopper else os.pipe()
        self.forward_stopper = os.pipe()
        self.tampering = self.should_tamper
        
        # parse data
        self.command = ''
        self.parse(data)
        self.integrity = True

        # allow forwarding immediately?
        if not self.should_tamper:
            self.forward()


    def parse(self, data):
        # parse given bytes (from socket, editor, file, ...)
        self.original = data
        self.command = data.decode().strip()
        fd_add_comment(self.forward_stopper, 'Request forward stopper' )
        

    
    def sanitize(self):
        self.command = self.command.replace('FUCK', '')


    def clone(self, should_tamper=False, no_stopper=True):
        return PTTP.create_request(self.bytes(), should_tamper, no_stopper) 

    def forward(self):
        self.tampering = False
        if self.forward_stopper:
            os.write(self.forward_stopper[1], b'1')

    def parse_method(self):
        pass

    def lines(self, headers=True, data=True, as_string=True):
        parts = []
        
        if headers or data:
            parts.append(self.command)
        return parts
        

    def __str__(self):
        return '\n'.join(self.lines())

    def bytes(self):
        return self.command.encode()








class PTTPResponse():

    def __init__(self, data, should_tamper, no_stopper=False):
        # set up tampering mechanism
        self.should_tamper = should_tamper
        self.forward_stopper = None if no_stopper else os.pipe()
        self.tampering = should_tamper
        
        
        # parse data
        self.response = ''
        self.data = data
        self.parse(data)

        
        # allow forwarding?
        if not self.should_tamper:
            self.forward()
    
    @staticmethod
    def spoof_regex(data):
        for old, new in weber.spoof_regexs.items():
            data = re.sub(old.encode(), new.encode(), data)
        return data

    def parse(self, data):
       self.command = data.decode()
       log.debug_parsing(self.command)
    
    def sanitize(self):
        self.command = self.command.replace('FUCK', '')

    def clone(self, should_tamper=True, no_stopper=True):
        return PTTP.create_response(self.bytes(), should_tamper, no_stopper)

    def forward(self):
        self.tampering = False
        if self.forward_stopper:
            os.write(self.forward_stopper[1], b'1')
 
    def lines(self, headers=True, data=True, as_string=True):
        parts = self.command.splitlines()
        return parts

    def __str__(self):
        return '\n'.join(self.lines())

    def bytes(self):
        return self.command.encode()
    
    def find_html_attr(self, tagstart, tagend, attr):
        # this method uses find_between() method to locate attributes and their values for specified tag
        # returns list of (absolute_position, match_string) of attributes
        tagmatches = find_between(self.command, tagstart, tagend)
        result = []
        for pos, _ in tagmatches:
            # find the end of the tagstart
            endpos = self.data.index(b'>', pos)
            linkmatches = find_between(self.data, b'%s="' % (attr), b'"', startpos=pos, endpos=endpos, inner=True)
            #if not linkmatches: # try without '"' # TODO should be done, but how to get good loffset in self.replace_links()?
            #    linkmatches = find_between(self.data, b'%s=' % (attr), b' ', startpos=pos, endpos=endpos, inner=True)
            result += linkmatches
        return result


    def find_tags(self, startends, attrs=None, valueonly=False):
        result = []
        if attrs is None:
            for startbytes, endbytes in startends:
                result += [x[1].decode() for x in find_between(self.data, startbytes, endbytes, inner=valueonly)]
        else:
            for (startbytes, endbytes), attr in zip(startends, attrs):
                result += [x[1].decode() for x in self.find_html_attr(startbytes, endbytes, attr)]
        return result


    def spoof(self, path):
        # replace data with file content
        try:
            with open(path, 'rb') as f:
                self.command = f.read().decode()
        except:
            log.err('Spoofing failed - cannot open file.')



