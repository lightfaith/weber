#!/usr/bin/env python3
"""
Proxy methods are defined here.
"""
#from http.server import BaseHTTPRequestHandler, HTTPServer
#import ssl
import os, socket, time, ssl, subprocess, traceback, threading, errno
from threading import Thread
#from collections import OrderedDict
from select import select
import requests

from source import weber
from source import log
from source.structures import Request, Response, URI
from source.lib import *



class ProxyLib():
    @staticmethod
    def recvall(conn):
        timeout = None # for the first recv
        chunks = []
        while True:
            conn.settimeout(timeout)
            timeout = 0.4
            try:
                recv_size = 65536
                log.debug_socket('Getting %d bytes...' % (recv_size))
                buf = conn.recv(recv_size)
                if not buf:
                    break
                chunks.append(buf)
            except socket.timeout:
                break
        #return result
        return b''.join(chunks)


class Proxy(Thread):
    def __init__(self, init_target=''):
        Thread.__init__(self)
        self.init_target = init_target
        self.threads = []
        self.terminate = False
        self.stopper = os.pipe()
        self.lock = threading.Lock()
        
        # set up server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((weber.config['proxy.host'][0], weber.config['proxy.port'][0]))

        # set up server socket for SSL
        self.ssl_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ssl_server_socket.bind((weber.config['proxy.host'][0], weber.config['proxy.sslport'][0]))
        self.ssl_server_socket = ssl.wrap_socket(self.ssl_server_socket, certfile=weber.config['proxy.sslcert'][0], keyfile=weber.config['proxy.sslkey'][0], server_side=True, do_handshake_on_connect=False)
        
        weber.mapping.add_init(self.init_target)

        # initialize tamper counters (for `trq <n>` and `trs <n>`)
        self.tamper_request_counter = 0
        self.tamper_response_counter = 0
        

    def stop(self):
        self.terminate = True
        os.write(self.stopper[1], b'1')
    
    def should_tamper(self, what):
        counter = self.tamper_request_counter if what == 'request' else self.tamper_response_counter
        default = weber.config.get('tamper.%ss' % (what), False)[0]
        # TODO domain, regex, mimetype matches
        if default:
            return True
        with self.lock:
            if counter > 0:
                counter -= 1
                return True
        return False


    def run(self):
        self.server_socket.listen(1)
        self.ssl_server_socket.listen(1)

        while True:
            r, _, _ = select([self.server_socket, self.ssl_server_socket, self.stopper[0]], [], [])
            # accept connection, thread it
            if not self.terminate:
                server_socket = None
                if self.server_socket in r:
                    server_socket = self.server_socket
                elif self.ssl_server_socket in r:
                    server_socket = self.ssl_server_socket
                if server_socket is None: # should not happen
                    continue
                try:
                    conn, client = server_socket.accept()

                    log.debug_socket('Connection accepted from \'%s:%d\':' % client)
                    # what process is contacting us?
                    netstat = subprocess.Popen('netstat -tpn'.split(), stdout=subprocess.PIPE)
                    o, _ = netstat.communicate()
                    for line in [line for line in o.splitlines() if list(filter(None, line.decode().split(' ')))[3] == '%s:%d' % (client)]:
                        log.debug_socket(line.decode())

                    # create new connection in new thread
                    t = ConnectionThread(conn, weber.rrdb.get_new_rrid(), self.should_tamper('request'), self.should_tamper('response'))
                    t.start()
                    if positive(weber.config.get('proxy.threaded')[0]):
                        self.threads.append(t)
                    else:
                        t.join()
                except socket.timeout:
                    pass
                except Exception as e:
                    log.err('Proxy error: '+str(e))
                    log.err('See traceback:')
                    traceback.print_exc()

            
            # terminate? end everything
            if self.terminate:
                for t in self.threads:
                    t.stop()
                time.sleep(0.1)
            
            # clean terminated connections
            threads_todel = [t for t in self.threads if not t.isAlive()]
            for t in threads_todel:
                t.join()
                self.threads.remove(t)

            # terminate and nothing runs anymore? 
            if self.terminate and len(self.threads) == 0:
                self.server_socket.shutdown(socket.SHUT_RDWR)
                self.ssl_server_socket.shutdown(socket.SHUT_RDWR)
                break


class ConnectionThread(Thread):
    def __init__(self, conn, rrid, tamper_request, tamper_response):
        Thread.__init__(self)
        self.conn = conn
        self.host = b'?'  # for thread printing
        self.port = 0      # for thread printing
        self.rrid = rrid
        self.path = '' # parsed from request, for `pt` command
        #self.ssl = (uri.scheme == 'https')
        self.tamper_request = tamper_request
        self.tamper_response = tamper_response
        self.stopper = os.pipe() # if Weber is terminated while tampering
        #print('new thread: uri', uri, type(uri))
        self.localuri = None

        self.keepalive = True
        self.terminate = False
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def stop(self):
        self.terminate = True
        os.write(self.stopper[1], b'1')

    def run(self):
        while self.keepalive:
            # receive request from browser
            request = self.receive_request()
            
            if request is None: # socket closed? socket problem?
                #log.debug_parsing('Request is broken, ignoring...')
                #return
                break

            self.keepalive = (request.headers.get(b'Connection') == b'Keep-Alive')
            
            # get URI() from request
            self.host, _, port = request.headers[b'Host'].partition(b':')
            self.port = int(port)
            self.localuri = URI(URI.build_str(self.host, self.port, request.path))
            log.debug_mapping('request source: %s ' % (str(self.localuri)))
            log.debug_parsing('\n'+'-'*15+'\n'+str(request)+'\n'+'='*20)
            self.path = request.path.decode()
            

            # change outgoing links
            remoteuri = weber.mapping.get_remote(self.localuri)
            if remoteuri is None:
                log.err('Cannot forward - local URI is not mapped. Terminating thread...')
                break
            request.path = remoteuri.path.encode()
            request.parse_method()
            request.headers[b'Host'] = remoteuri.domain.encode() if remoteuri.port in [80, 443] else b'%s:%d' % (remoteuri.domain, remoteuri.port)
            log.debug_parsing('\n'+str(request)+'\n'+'#'*20)
            
            weber.rrdb.add_request(self.rrid, request)
            
            # tamper request
            if request.tampering and positive(weber.config['overview.realtime'][0]):
                log.tprint('\n'.join(weber.rrdb.overview(['%d' % self.rrid], header=False)))
            r, _, _ = select([request.forward_stopper[0], self.stopper[0]], [], [])
            if self.stopper[0] in r:
                # Weber is terminating
                break
            request = weber.rrdb.rrs[self.rrid].request # reload in case it's modified

            # forward request to server        
            log.debug_socket('Forwarding request... (%d B)' % (len(request.data)))
            response = self.forward(remoteuri, request.bytes())

            if response is None:
                break

            log.debug_parsing('\n'+str(response)+'\n'+'='*30)
            
            weber.rrdb.add_response(self.rrid, response)
            
            # tamper response
            if response.tampering and positive(weber.config['overview.realtime'][0]):
                log.tprint('\n'.join(weber.rrdb.overview(['%d' % self.rrid], header=False)))
            r, _, _ = select([response.forward_stopper[0], self.stopper[0]], [], [])
            if self.stopper[0] in r:
                # Weber is terminating
                break
            response = weber.rrdb.rrs[self.rrid].response # reload in case it's modified

            # spoof if desired (with or without GET arguments)
            spoof_path = remoteuri.get_value() if positive(weber.config['spoof.arguments'][0]) else remoteuri.get_value().partition('?')[0]
            if spoof_path in weber.spoofs.keys():
                response.spoof(weber.spoofs[spoof_path])

            # alter redirects # TODO test 302, 303
            if response.statuscode in [301, 302, 303]:
                newremote = URI(response.headers[b'Location'])
                newlocal = weber.mapping.get_local(newremote)
                response.headers[b'Location'] = newlocal.__bytes__()
                response.statuscode = 302 # TODO just for debugging

            # TODO change incoming links - probably complete
            for tagname, attr_key, attr_value in Response.link_tags:
                olds = response.find_tags(tagname, attr_key=attr_key, attr_value=attr_value, form='soup')
                for old in olds:
                    old_value = old[attr_key]
                    if old_value.partition('://')[0] in ('http', 'https'):
                        new = weber.mapping.get_local(old_value)
                        old[attr_key] = new.get_value()
                        #print('new', old)

            log.debug_parsing('\n'+str(response)+'\n'+'-'*30)

            # send response to browser
            try:
                self.send_response(response)
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
            time.sleep(10)
        self.conn.close()


    def receive_request(self):
        try:
            request = Request(ProxyLib.recvall(self.conn), self.tamper_request)
            if not request.integrity:
                log.debug_socket('Request is weird - length is zero')
                self.conn.close()
                return None
            return request
        except IOError:
            log.debug_socket('Request socket is not accessible anymore - terminating thread.')
            #log.err('See traceback:')
            #traceback.print_exc()
            return None
        except Exception as e:
            log.err('Proxy receive error: '+str(e))
            log.err('See traceback:')
            traceback.print_exc()
            return None

        log.debug_socket('Request received.') 
    

    def forward(self, uri, data):
        try:
            self.client_socket.connect((uri.domain, uri.port))
        except socket.gaierror:
            log.err('Cannot connect to %s:%d' % (uri.domain, uri.port))
            return None

        if uri.scheme == 'https':
            self.client_socket = ssl.wrap_socket(self.client_socket)
        self.client_socket.send(data)
        try:
            response = Response(ProxyLib.recvall(self.client_socket), self.tamper_response)
            self.client_socket.close()
            return response
        except Exception as e:
            log.err(e)
            log.err('See traceback:')
            traceback.print_exc()
            return None

    
    def send_response(self, response):
        if response is not None:
            log.debug_socket('Forwarding response (%d B).' % len(response.data))
            self.conn.send(response.bytes())

            log.debug_socket('Response sent.')
        else:
            log.debug_parsing('Response is weird.')
 

"""
class SSLPasser(Thread):
    def __init__(self, browser, server):
        Thread.__init__(self)
        self.browser = browser
        self.server = server
        self.terminate = False

    def stop(self):
        self.terminate = True

    def run(self):
        sockets = [self.browser, self.server]
        log.debug_socket('SSLPasser executed.')
        while True:
            try:
                readable, writable, exceptional = select(sockets, [], [], 2)
                if not (readable or writable or exceptional): # timeout
                    break
                if self.browser in readable:
                    self.forward(self.browser, self.server)
                if self.server in readable:
                    self.forward(self.server, self.browser)
            except ConnectionResetError:
                self.termiate = True
            if self.terminate:
                break
        log.debug_socket('SSLPasser quits.')
                

    def forward(self, src, dest):
        try:
            data = src.recv(65536)
            dest.send(data)
        except:
            self.terminate = True
"""



