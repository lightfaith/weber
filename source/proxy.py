#!/usr/bin/env python3
"""
Proxy methods are defined here.
"""
#from http.server import BaseHTTPRequestHandler, HTTPServer
#import ssl
import socket, time, ssl, subprocess
from threading import Thread
#from collections import OrderedDict
from select import select
import requests
import os

from source import weber
from source import log
from source.structures import Request, Response
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
                recv_size = 4096
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
        
        # set up server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((weber.config['proxy.host'], weber.config['proxy.port']))

        # set up server socket for SSL
        self.ssl_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssl_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ssl_server_socket.bind((weber.config['proxy.host'], weber.config['proxy.sslport']))
        self.ssl_server_socket = ssl.wrap_socket(self.ssl_server_socket, certfile='cert.pem', keyfile='key.pem', server_side=True, do_handshake_on_connect=True)
        
        weber.mapping.add_init(self.init_target)
        

    def stop(self):
        self.terminate = True
        os.write(self.stopper[1], b'1')
    
    def run(self):
        self.server_socket.listen(1)
        #self.server_socket.settimeout(2) # TODO no busy-waiting
        self.ssl_server_socket.listen(1)
        #self.ssl_server_socket.settimeout(2) # TODO no busy-waiting

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
                    t = ConnectionThread(conn, weber.mapping.init_target, weber.rrdb.get_new_rrid())
                    t.start()
                    if positive(weber.config.get('proxy.threaded')):
                        self.threads.append(t)
                    else:
                        t.join()
                except socket.timeout:
                    pass
                except Exception as e:
                    log.err('Proxy error: '+str(e))
            
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
    def __init__(self, conn, uri, rrid):
        Thread.__init__(self)
        self.conn = conn
        self.host = uri.domain
        self.port = uri.port
        self.rrid = rrid
        self.path = '' # parsed from request, for `pt` command
        self.ssl = (uri.scheme == 'https')
        
        self.keepalive = True
        self.terminate = False
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def stop(self):
        self.terminate = True

    def run(self):
        while self.keepalive:
            # receive request from browser
            request = self.receive_request()
            
            if request is None: # socket closed? socket problem?
                #log.debug_parsing('Request is broken, ignoring...')
                #return
                break
            
            log.debug_parsing('\n'+'-'*15+'\n'+str(request)+'\n'+'='*20)
            self.path = request.path
            """
            # SSLPasser if CONNECT
            if request.method == b'CONNECT':
                log.debug_socket('Will SSLPass to %s:%d' % (request.host, request.port))
                self.client_socket.connect((request.host, request.port))
                self.conn.send(b'%s 200 OK\r\n\r\n' % (request.version)) # hit it :)
                SSLPasser(self.conn, self.client_socket).start()
                return
            """
            
            self.keepalive = (request.headers.get(b'Connection') == b'Keep-Alive')

            # TODO change outgoing links (probably complete)
            if request.path.startswith(b'/WEBER-MAPPING/'):
                request.path = weber.mapping.get_remote(weber.mapping.get_local_uri_from_hostport_path(request.headers[b'Host'], request.path).__bytes__()).path.encode()
                request.parse_method()
                log.debug_mapping(weber.mapping.l_r.items()) # TODO enhance debug of mapping
            request.headers[b'Host'] = weber.mapping.get_remote_hostport(request.headers[b'Host'])
            log.debug_parsing('\n'+str(request)+'\n'+'#'*20)
            
            # TODO tamper request
            weber.rrdb.add_request(self.rrid, request)


            # forward request to server        
            log.debug_socket('Forwarding request... (%d B)' % (len(request.data)))
            """
            if self.domain != request.headers.get('Host'):
                log.debug_socket('Forwarding request... (%d B)' % (len(request.data)))
                response = self.forward(request.host, request.port, request.bytes())
            log.debug_socket('Response received.')
            """
            # TODO PLAIN/SSL
            response = self.forward(self.host, self.port, request.bytes()) # TODO consistent with changed link (check)
            log.debug_parsing('\n'+str(response)+'\n'+'='*30)
            
            # TODO tamper response
            weber.rrdb.add_response(self.rrid, response)

            # TODO change incoming links - probably complete
            for tagname, attr_key, attr_value in Response.link_tags:
                olds = response.find_tags(tagname, attr_key=attr_key, attr_value=attr_value, form='soup')
                for old in olds:
                    old_value = old[attr_key]
                    scheme, _, _ = old_value.partition('://')
                    if scheme in ('http', 'https'):
                        new, _ = weber.mapping.generate(old_value, scheme)
                        old[attr_key] = new.get_value()
                        #print('new', old)

            log.debug_parsing('\n'+str(response)+'\n'+'-'*30)

            # send response to browser
            self.send_response(response)

            # print if desired
            if positive(weber.config['overview.realtime']):
                log.tprint('\n'.join(weber.rrdb.overview(['%d' % self.rrid], header=False)))
            time.sleep(10)


    def receive_request(self):
        try:
            request = Request(ProxyLib.recvall(self.conn))
            if not request.integrity:
                log.debug_socket('Request is weird - length is zero')
                self.conn.close()
                return None
            return request
        except IOError:
            log.debug_socket('Request socket is not accessible anymore - terminating thread.')
            return None
        except Exception as e:
            log.err('Proxy receive error: '+str(e))
            return None

        log.debug_socket('Request received.') 
    

    def forward(self, host, port, data):
        self.client_socket.connect((host, port))
        if self.ssl:
            self.client_socket = ssl.wrap_socket(self.client_socket)
        self.client_socket.send(data)
        try:
            response = Response(ProxyLib.recvall(self.client_socket))
            self.client_socket.close()
            return response
        except Exception as e:
            log.err(e)
            return None

    
    def send_response(self, response):
        if response is not None:
            log.debug_socket('Forwarding response (%d B).' % len(response.data))
            self.conn.send(response.bytes())
            log.debug_socket('Response sent.')
        else:
            log.debug_parsing('Response is weird.')
        self.conn.close()
 

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
            data = src.recv(4096)
            dest.send(data)
        except:
            self.terminate = True
"""



