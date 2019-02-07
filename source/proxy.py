#!/usr/bin/env python3
"""
Proxy methods are defined here.
"""
import errno
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import traceback
from select import select
from datetime import datetime

from source import weber
from source import log
from source.structures import Server, URI, RR
from source.lib import *
from source.fd_debug import *
from source.protocols import protocols

class ProxyLib():
    """

    """
    @staticmethod
    #def recvall(conn, comment, stopper):
    def recvall(conn, comment):
        conn.setblocking(0)
        chunks = []
        begin = time.time()
        timeout = weber.config['proxy.socket_timeout'].value
        log.debug_socket('Trying to receive data from %s...' % (comment))
        while True:
            if chunks and time.time()-begin > timeout:
                break
            elif time.time()-begin > 2*timeout:
                break
            try:
                buf = conn.recv(65536)
                if buf:
                    chunks.append(buf)
                    begin = time.time()
            except Exception as e:
                """no data ready, just continue waiting"""
                time.sleep(0.1)
                pass

        result = b''.join(chunks)
        log.debug_socket('Received %d bytes.' % (len(result)))
        return result

        '''
        """

        """
        timeout = None # for the first recv
        chunks = []
        # TODO fix looping
        while True:
            #print('sleeping for a while')
            #time.sleep(1) # TODO delete after testing
            conn.settimeout(timeout)
            try:
                recv_size = 65536
                #r, _, _ = select([conn], [], [], timeout)
                log.debug_socket('Getting %d bytes from %s...' 
                                 % (recv_size, comment))
                #if conn in r:
                if True:
                    buf = conn.recv(recv_size)
                #else:
                #    print('select timeout.')
                #    break
                #print('Got', len(buf), 'B')
                #print('BUF:', buf, type(buf), bool(buf))
                if not buf:
                    print('Nothing loaded in this recvall iteration, returning (not buf)')
                    break
                    ''''''
                    # TODO test so no spams
                    """nothing loaded? wait for new input"""
                    if not chunks:
                        print("Waiting for new input")
                        r, _, _ = select([conn, stopper], [], [])
                        """or terminate if asked"""
                        if stopper in r:
                            print('Recvall is terminating.')
                            break
                        elif conn in r:
                            print('Connection awoken the recvall select.')
                    ''''''
                chunks.append(buf)
            except socket.timeout:
                """no more data recently, return what we have"""
                print('recvall stopping (socket.timeout)')
                break
            """set timeout for the next round"""
            timeout = 0.4
        return b''.join(chunks)
        '''
    @staticmethod
    def spoof_regex(data, translations):
        """

        """
        for old, new in translations:
            data = re.sub(old.encode(), new.encode(), data)
        return data


class Proxy(threading.Thread):
    """

    """
    def __init__(self, listen_host, listen_port):
        """

        """
        threading.Thread.__init__(self)
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.stopper = os.pipe()
        self.terminate = False
        self.threads = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(
            socket.SOL_SOCKET, 
            socket.SO_REUSEADDR, 
            1)
        try:
            self.socket.bind((self.listen_host, self.listen_port))
        except Exception as e:
            log.err('Cannot bind: %s' % (str(e)))
            exit_program(-1, None)
        log.debug_flow('Proxy created.')

    def stop(self):
        """

        """
        self.terminate = True
        os.write(self.stopper[1], b'1')
        log.debug_flow('Proxy ordered to terminate.')

    def run(self):
        """

        """
        log.debug_flow('Proxy started.')
        try:
            self.socket.listen(1)
        except Exception as e:
            log.err('Cannot listen:', str(e))
            return

        """main proxy loop"""
        while True:
            r, _, _ = select([self.socket, self.stopper[0]], [], [])
            if self.terminate:
                """termination request? send signal to all threads"""
                log.debug_flow('Proxy terminating all ConnectionThreads.')
                for t in self.threads:
                    t.stop()
                time.sleep(0.1)
            else:
                """new connection, accept it"""
                try:
                    conn, client = self.socket.accept()
                    log.debug_socket('Connection accepted from \'%s:%d\'' 
                                     % client)
                    log.debug_flow('Proxy creating new ConnectionThread.')
                    """run new thread with accepted socket"""
                    t = ConnectionThread(conn)
                    t.start()
                    """add thread to array OR wait for it"""
                    if weber.config['proxy.threaded'].value:
                        self.threads.append(t)
                    else:
                        t.join()
                except socket.timeout:
                    pass
                except:
                    log.err('Proxy error.')
                    traceback.print_exc()
            """clean terminated threads"""
            threads_todel = [t for t in self.threads if not t.isAlive()]
            for t in threads_todel:
                t.join()
                self.threads.remove(t)
            """terminate and all threads joined?"""
            if self.terminate and not self.threads:
                self.socket.shutdown(socket.SHUT_RDWR)
                break
        """end of main proxy loop"""
        log.debug_flow('Proxy stopped.')


class ConnectionThread(threading.Thread):
    """
    

    Attributes:
        downstream_socket () - socket from browser
        
    """
    def __init__(self, downstream_socket, from_weber=False):
        """
        
        """
        threading.Thread.__init__(self)
        self.downstream_socket = downstream_socket
        self.from_weber = from_weber
        self.request = None
        self.response = None
        self.rrid = None # for one loop run only, but accesssed from functions
        self.terminate = False
        self.stopper = os.pipe() # to allow new request
        self.server_id = None # TODO not necessary if self.server is used?
        self.server = None
        self.full_uri = None # for one loop run only, but accessed from functions
        self.upstream_socket = None
        self.connect_method = False
        self.can_forward_request = True # TODO from option
        self.can_forward_response = True # TODO from option
        self.protocol = weber.protocols['http']
        self.times = {} # for one loop run only, but accessed from functions
    
    def send_continuation_signal(self):
        if self.stopper:
            os.write(self.stopper[1], b'1')
    
    def wait_for_continuation_signal(self):
        """

        """
        r, _, _ = select([self.stopper[0]], [], [])

    def stop(self):
        """
        
        """
        self.terminate = True
        """send continuation signal in case we are tampering"""
        self.send_continuation_signal()

    def add_request(self, request):
        """Adds request bytes manually.

        If the Request-Response pair is a copy, use known Request data.
        
        Args:
            request (): 
        """
        self.request = request
        # TODO not fully implemented / tested


    def run(self):
        """

        """
        first_run = True
        keepalive = False if self.from_weber else True
        """send signal so first request can be processed"""
        #self.send_continuation_signal()

        while keepalive or first_run:
            """wait for signal - cause previous request can be tampered"""
            #self.wait_for_continuation_signal()
            if self.terminate: break
            #time.sleep(0.5) # TODO delete after testing recvall loops
            """reset times dictionary for new traffic"""
            self.times = {}
          
            """read request from socket if needed"""
            if not self.from_weber:
                request_raw = ProxyLib.recvall(self.downstream_socket, 
                                               comment='downstream')
                self.times['request_received'] = datetime.now()
                '''
                if not self.request.integrity:
                    log.debug_socket('Request integrity failure.')
                    self.downstream_socket.close()
                else:
                '''
                log.debug_socket('Request received.')
            
            if self.terminate: break
            """convert to protocol-specific object"""
            self.request = self.protocol.create_request(request_raw)
            if not self.request.integrity:
                log.debug_protocol('Received request is invalid.')
                self.send_response(b'HTTP/1.1 400 Bad Request\r\n\r\n!') #TODO all right?
                #continue
                break # OK cause 1 ConnectionThread deals with only 1 request

            """provide Weber page with CA if path == /weber"""
            if self.request.path == b'/weber':
                self.send_response(b'HTTP/1.1 200 OK\r\n\r\nWeber page WORKS!')
                # TODO return CA and stuff
                break

            '''
            # TEST SSL # WORKS!!!!!!
            if self.request.path == b'seznam.cz:443':
                self.send_response(b'HTTP/1.1 200 OK\r\n\r\n')
                self.downstream_socket = ssl.wrap_socket(
                        self.downstream_socket, 
                        certfile='ssl/pki/issued/seznam.cz.crt',
                        keyfile='ssl/pki/private/seznam.cz.key',
                        do_handshake_on_connect=True,
                        server_side=True,
                        )
                print(ProxyLib.recvall(self.downstream_socket, 'downstream'))
                self.send_response(b'HTTP/1.1 200 OK\r\n\r\nWeber page WORKS!')
                # TODO return CA and stuff
                break
            '''
            """get actual full_uri"""
            if self.connect_method:
                self.full_uri = self.server.uri.clone()
                self.full_uri.path = self.request.path.decode()
            else:
                self.full_uri = URI(self.request.path) # TODO try for non-proxy requests?
                
            log.debug_flow('Full URI determined: %s' % self.full_uri.tostring())
            #print(s for s, _ in weber.servers.items())
            """respond to CONNECT methods, create server"""
            """or parse http request and create server"""
            if not self.server:
                """get valid URI"""
                server_uri_str = self.full_uri.tostring(path=False)
                """create or get existing server"""
                self.server = weber.servers[
                                  Server.create_server(server_uri_str, 
                                                       self.protocol)]
                """stop this Connection if Server had problems"""
                if self.server.problem:
                    log.debug_server(
                        'Server is a troublemaker, ignoring the request.')
                    self.send_response(b'HTTP/1.1 418 I\'m a teapot\r\n\r\n!') #TODO all right?
                    break
                """create socket to server"""
                self.upstream_socket = socket.socket(socket.AF_INET, 
                                                     socket.SOCK_STREAM)
                #self.upstream_socket.setsockopt(socket.SOL_SOCKET, 
                #                                socket.SO_KEEPALIVE, 
                #                                1)
                try:
                    self.upstream_socket.connect((self.server.uri.domain,
                                                  self.server.uri.port))
                except Exception as e:
                    print('Upstream connect error for %s:' % (self.full_uri.tostring()), str(e))

                """was it CONNECT?"""
                if self.request.method == b'CONNECT':
                    """send confirmation response"""
                    self.connect_method = True
                    log.debug_flow('Accepting CONNECTion.')
                    self.send_response(b'HTTP/1.1 200 OK\r\n\r\n')
                else:
                    """not connect -> remove server from req path"""
                    self.request.path = self.request.path[
                         self.request.path.find(
                             b'/', 
                             len(self.server.uri.scheme)+3):]
                """upgrade both sockets if SSL"""
                if self.server.ssl:
                    log.debug_socket('Upgrading sockets to SSL.')
                    self.downstream_socket.setblocking(True)
                    #self.upstream_socket.setblocking(True)
                    self.upstream_socket = ssl.wrap_socket(self.upstream_socket)
                    try:
                        self.downstream_socket = ssl.wrap_socket(
                            self.downstream_socket, 
                            certfile=self.server.certificate_path,
                            keyfile=self.server.certificate_key_path,
                            #do_handshake_on_connect=True,
                            server_side=True)
                    except Exception as e:
                        log.err('Upgrading to SSL failed: %s' % str(e))
                        continue
                """continue listening if it was CONNECT"""
                if self.request.method == b'CONNECT':
                    continue
                    
            '''
            # TODO test; del
            print('sending test response')
            self.send_response(b'HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nWeber page WORKS!')
            continue
            '''
            
            """request and server are done, time to play with it"""
            self.rrid = weber.rrdb.get_new_rrid()
            weber.rrdb.add_request(self.rrid, 
                                   self.request, 
                                   self.server, 
                                   self.times)
            if self.terminate: break
            self.request.pre_tamper()
            """tamper/forward request"""
            if not self.can_forward_request:
                log.debug_tampering('Request is tampered.')
                self.times['request_tampered'] = datetime.now()
                """tampering; print overview if appropriate"""
                if positive(
                        weber.config['interaction.realtime_overview'].value):
                    # TODO RRDB overview of this
                    log.tprint(' '.join(weber.rrdb.overview(
                                        [str(self.rrid)],
                                        header=False)))
            else:
                log.debug_tampering('Forwarding request without tampering.')
                self.continue_forwarding()
            """
            following parts are in continue_forwarding method,
            as those can happen much later
            """
            """terminate loop - no keepalive"""  # TODO is that normal?
            keepalive = False
        """
        wait for tampered request to be processed if keepalive
        is off, ignore if termination is in effect.
        """
        if not self.terminate:
            self.wait_for_continuation_signal()
        """cleanup"""
        log.debug_flow('Closing sockets and stopper for ConnectionThread.')
        if self.upstream_socket:
            self.upstream_socket.close()
        if self.downstream_socket:
            self.downstream_socket.close()
        if self.stopper:
            for fd in (0, 1):
                os.close(self.stopper[fd])
            self.stopper = None
        log.debug_flow('ConnectionThread terminated.')
        """end of ConnectionThread run() method"""

    def continue_forwarding(self):
        """

        """
        # TODO if from weber and brute is set: replace; maybe in post_tamper method
        if not self.request:
            log.err('Tried to forward non-existent request.')
            return
        self.request.post_tamper()
        self.server.get_rps_approval() # sleep for RPS limiting
        if self.terminate: return
        self.times['request_forwarded'] = datetime.now()
        response_raw = self.forward(self.request.bytes())
        if not response_raw:
            log.err('Response is empty!')
            return # TODO what to do exactly?
        self.times['response_received'] = datetime.now()
        if self.terminate: return
        self.response = self.protocol.create_response(response_raw)
        weber.rrdb.add_response(self.rrid, self.response)
        self.response.pre_tamper()
        
        if self.terminate: return
        """save response data into folder tree if desired"""
        if weber.config['crawl.save_path'].value:
            if (self.response.statuscode >= 200 
                    and self.response.statuscode < 300):
                # TODO what about custom error pages? but probably not...
                # TODO test content-length and 0 -> directory?
                log.debug_flow('Saving response data into file.')
                file_path = create_folders_from_uri(
                    weber.config['crawl.save_path'].value,
                    self.full_uri.tostring()) 
                while True:
                    """Write file, try different approach if problem"""
                    try:
                        with open(file_path, 'wb') as f:
                            f.write(self.response.bytes(headers=False))
                            break
                    except OSError as e:
                        if '[Errno 36]' in str(e):
                            """File name too long, use RRID"""
                            file_path = (file_path.rpartition('/')[0] 
                                         + str(self.rrid))
                    except Exception as e:
                        log.err('Cannot save response data for %s!' 
                                % self.full_uri)
                        log.err(str(e))
                        break

        """tamper/forward response"""
        if not self.can_forward_response:
            log.debug_tampering('Response is tampered.')
            self.times['response_tampered'] = datetime.now()
            """tampering; print overview if appropriate"""
            if positive(
                    weber.config['interaction.realtime_overview'].value):
                log.tprint(' '.join(weber.rrdb.overview(
                                   [str(self.rrid)],
                                   header=False)))
        else:
            log.debug_tampering('Forwarding response without tampering.')
            self.continue_sending_response()
        """
        following parts are in continue_sending_response method,
        as those can happen much later
        """
    
    def continue_sending_response(self):
        """

        """
        if not self.response:
            log.err('Tried to forward non-existent response.')
            return
        self.response.post_tamper(self.full_uri)
        if self.terminate: return
        """print overview if desired"""
        if positive(
                weber.config['interaction.realtime_overview'].value):
            log.tprint(' '.join(weber.rrdb.overview(
                               [str(self.rrid)],
                               header=False)))
        self.send_response(self.response.bytes(encode=True))
        self.times['response_forwarded'] = datetime.now()
        """allow new request"""
        self.send_continuation_signal()


    def forward(self, data):
        if self.upstream_socket:
            log.debug_flow('Forwarding request to server.')
            log.debug_socket('Forwarding request... (%d B)' 
                             % (len(data)))
            self.upstream_socket.send(data)
            result = ProxyLib.recvall(self.upstream_socket, 
                                      comment='upstream')
            if result:
                log.debug_flow('Response received from server.')
                return result
            #else:
            #    weber.forward_fail_uris.append(str(self.localuri))
            #    return b''
        else:
            log.err('No upstream socket - cannot forward.')
            return b''


    def send_response(self, data):
        """
        Uses self.downstream_socket socket to send data back to browser.

        Args:
            data (bytes): data to send
        """
        """stop if originating from Weber"""
        if self.from_weber:
            log.debug_socket('Weber origin -> not sending response.')
            return

        if data:
            log.debug_socket('Forwarding response (%d B).' % len(data))
            try:
                self.downstream_socket.send(data)
                log.debug_socket('Response sent.')
            except ssl.SSLZeroReturnError:
                log.err('SSL Connection to client for %s has been closed.'
                        % self.full_uri)
            except BrokenPipeError:
                log.err('Socket to client for %s has been closed.'
                        % self.full_uri)
        else:
            log.debug_parsing('Response is weird.')
        

'''
class ConnectionThread(threading.Thread):
    def __init__(self, conn, local_port, rrid, tamper_request, tamper_response, template_rr=None, request_modifier=None, Protocol=None):
        # conn - socket to browser, None if from template
        # local_port - port of conn socket
        # rrid - index of request-response pair
        # tamper_request - should the request forwarding be delayed?
        # tamper_response - should the response forwarding be delayed?
        # template_rr - known request (e.g. copy of existing for bruteforcing) - don't communicate with browser if not None
        # request_modifier - function to alter request (e.g. fault injection, brute values)
        threading.Thread.__init__(self)
        self.Protocol = Protocol

        self.conn = conn
        self.local_port = local_port
        self.host = b'?'  # for thread printing
        self.port = 0      # for thread printing
        self.rrid = rrid
        self.path = '' # parsed from request, for `pt` command
        self.tamper_request = tamper_request
        self.tamper_response = tamper_response
        self.template_rr = template_rr
        self.request_modifier = request_modifier
        #print('New ConnectionThread, tampering request', self.tamper_request, ', response', self.tamper_response)
        self.stopper = os.pipe() # if Weber is terminated while tampering
        fd_add_comment(self.stopper, 'CT (RRID %d) stopper' % (rrid))
        #print('new thread: uri', uri, type(uri))
        self.localuri = None
        self.remoteuri = None

        self.keepalive = True
        self.terminate = False
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def stop(self):
        self.terminate = True
        if self.stopper:
            os.write(self.stopper[1], b'1')

    def run(self):
        # implemented for each specific protocol
        pass 


    def receive_request(self, request_modifier=None):
        if not self.Protocol:
            log.debug_socket('Receiving request for unknown protocol, aborting.')
            return None
        try:
            # set request_modifier to do nothing if not defined
            request = self.Protocol.create_request(ProxyLib.recvall(self.conn), self.tamper_request, request_modifier)
            if not request.integrity:
                log.debug_socket('Request integrity failure...')
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
        if not self.Protocol:
            return None
        try:
            self.client_socket.connect((uri.domain, uri.port))
        except socket.gaierror:
            log.err('Cannot connect to %s:%d' % (uri.domain, uri.port))
            return None
        except ConnectionRefusedError:
            log.err('Cannot connect to %s:%d (connection refused)' % (uri.domain, uri.port))
            return None
        except TimeoutError:
            log.err('Site is not accessible (timeout).')
            return None

        if uri.scheme == self.Protocol.ssl_scheme:
            try:
                self.client_socket = ssl.wrap_socket(self.client_socket)
            except Exception as e:
                #log.err('Cannot create SSL socket for %s: %s' % (uri.get_value(), str(e)))
                #log.err('See traceback:')
                #traceback.print_exc()
                #return None
                log.debug_socket('Cannot create SSL socket for %s, using plaintext transmission instead.' % (uri.get_value()))
                # recreate socket, run forward with HTTP
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                uri.scheme = self.Protocol.scheme # TODO uri changed everywhere? (mapping?)
                self.client_socket.connect((uri.domain, uri.port))
                #return self.forward(uri, data)
        log.debug_socket('Forwarding request to server...')
        self.client_socket.send(data)
        try:
            response = self.Protocol.create_response(ProxyLib.recvall(self.client_socket), self.tamper_response)
            self.client_socket.close()
            return response
        except Exception as e:
            log.err(e)
            log.err('See traceback:')
            traceback.print_exc()
            return None

    
 '''
