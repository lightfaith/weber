#!/usr/bin/env python3
"""
Proxy methods are defined here.
"""
from source import weber
from source import log
from source.structures import Request, Response

#from http.server import BaseHTTPRequestHandler, HTTPServer
#import ssl
import requests
import socket
import time
from threading import Thread
#from collections import OrderedDict
from select import select


class ProxyLib():
    def recvall(conn):
        timeout = None # for the first recv
        chunks = []
        while True:
            conn.settimeout(timeout)
            timeout = 0.5
            try:
                log.debug_socket('Getting 1024 bytes...')
                buf = conn.recv(1024)
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
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((weber.config['proxy.host'], weber.config['proxy.port']))
        #self.server_socket = ssl.wrap_socket(server.socket, certfile='server.pem', server_side=True)

        weber.mapping.add_init(self.init_target)
        

    def stop(self):
        self.terminate = True
    
    def run(self):
        self.server_socket.listen(1)
        self.server_socket.settimeout(2)

        while True:
            # accept connection, thread it
            if not self.terminate:
                try:
                    conn, _ = self.server_socket.accept()

                    log.debug_socket('Connection accepted...')
                    t = ConnectionThread(conn, weber.mapping.init_target, weber.rrdb.get_new_rrid())
                    t.start()
                    if weber.config.get('proxy.threaded'):
                        self.threads.append(t)
                    else:
                        t.join()
                except socket.timeout:
                    pass
            
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
                break


class ConnectionThread(Thread):
    def __init__(self, conn, uri, rrid, ssl=False):
        Thread.__init__(self)
        self.conn = conn
        self.host = uri.domain
        self.port = uri.port
        self.rrid = rrid
        self.ssl = ssl
        self.terminate = False
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def stop(self):
        self.terminate = True

    def run(self):
        # receive request from browser
        request = self.receive_request()
        log.debug_mapping(weber.mapping.l_r.items())
        """
        # SSLPasser if CONNECT
        if request.method == b'CONNECT':
            log.debug_socket('Will SSLPass to %s:%d' % (request.host, request.port))
            self.client_socket.connect((request.host, request.port))
            self.conn.send(b'%s 200 OK\r\n\r\n' % (request.version)) # hit it :)
            SSLPasser(self.conn, self.client_socket).start()
            return
        """
        log.debug_parsing('\n'+'-'*15+'\n'+str(request)+'\n'+'='*20)
        
        if request is None:
            log.debug_parsing('Request is broken, ignoring...')
            return
        
        # TODO change links
        request.headers[b'Host'] = weber.mapping.get_remote_hostport(request.headers[b'Host'])
        log.debug_parsing('\n'+str(request)+'\n'+'#'*20)
        # TODO tamper request


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
        # TODO change links

        log.debug_parsing('\n'+str(response)+'\n'+'-'*30)
        
        # send response to browser
        self.send_response(response)
        #input()


    def receive_request(self):
        try:
            request = Request(ProxyLib.recvall(self.conn))
            if not request.integrity:
                log.debug_socket('Request is weird - length is zero')
                self.conn.close()
                return None
            return request
        except Exception as e:
            log.err(e)
            return None

        log.debug_socket('Request received.') 
    

    def forward(self, host, port, data):
        self.client_socket.connect((host, port))
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



