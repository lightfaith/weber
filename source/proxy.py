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

from source.watcher import Watcher # TODO for debugging

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
        """ wait longer for expected response"""
        wait_value = 10 if comment == 'upstream' else 1
        while True:
            if chunks and time.time()-begin > 0.5 * timeout:
                break
            elif time.time()-begin > wait_value * timeout:
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

    @staticmethod
    def spoof_regex(data, translations):
        """

        """
        for old, new in translations:
            data = re.sub(old.encode(), new.encode(), data)
        return data

class TamperController():
    """
    Thread-safe mechanism to choose requests/responses to be tampered.
    Created and set in proxy, sent to ConnectionThreads as init arg.
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.tamper_request_count = 0
        self.tamper_response_count = 0

    def set_tamper_request_count(self, count):
        with self.lock:
            log.debug_tampering('Setting new tamper request count value: %d' 
                                % count)
            self.tamper_request_count = count
            
    def set_tamper_response_count(self, count):
        with self.lock:
            log.debug_tampering('Setting new tamper response count value: %d' 
                                % count)
            self.tamper_response_count = count
            
    def ask_for_request_tamper(self):
        """
        Returns:
            whether default_tamper OR tamper counter allows it (bool)
        """
        if positive(weber.config['tamper.requests'].value):
            """default tamper? allow it"""
            log.debug_tampering('Tampering request because of default value.')
            return True
        """count OK?"""
        with self.lock:
            result = self.tamper_request_count > 0
            if result:
                self.tamper_request_count -= 1
                log.debug_tampering(
                    'Tampering request because of count (%d remaining)'
                    % self.tamper_request_count)
        return result

    def ask_for_response_tamper(self):
        """
        Returns:
            whether default_tamper OR tamper counter allows it (bool)
        """
        if positive(weber.config['tamper.responses'].value):
            """default tamper? allow it"""
            log.debug_tampering('Tampering response because of default value.')
            return True
        """count OK?"""
        with self.lock:
            result = self.tamper_response_count > 0
            if result:
                self.tamper_response_count -= 1
                log.debug_tampering(
                    'Tampering response because of count (%d remaining)'
                    % self.tamper_response_count)
        return result


class Proxy(threading.Thread):
    """

    """
    def __init__(self, listen_host, listen_port):
        """

        """
        threading.Thread.__init__(self)
        self.tamper_controller = TamperController()
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
                    t = ConnectionThread(conn, self.tamper_controller)
                    t.start()
                    """add thread to array OR wait for it"""
                    if positive(weber.config['proxy.threaded'].value):
                        self.threads.append(t)
                    else:
                        t.join()
                except socket.timeout:
                    pass
                except:
                    log.err('Proxy error.')
                    traceback.print_exc()
            """clean terminated threads"""
            self.clean_threads()
            """terminate and all threads joined?"""
            if self.terminate and not self.threads:
                self.socket.shutdown(socket.SHUT_RDWR)
                break
        """end of main proxy loop"""
        log.debug_flow('Proxy stopped.')

    def clean_threads(self):
        """
        Clean all terminated threads.
        """
        threads_todel = [t for t in self.threads if not t.isAlive()]
        for t in threads_todel:
            try:
                t.join()
                self.threads.remove(t)
            except:
                """race condition; ignore"""
                pass

    def duplicate(self, rrid, force_tamper_request=False):
        """
        Duplicates request of given RRID and runs it as 
        new ConnectionThread (with from_weber set to True).

        Returns:
            reference to thread (ConnectionThread)
            RRID (int)
            reference to Request (Request)
        """
        """run new ConnectionThread"""
        log.debug_flow('Creating new ConnectionThread from Weber (duplicate).')
        t = ConnectionThread(None, 
                             self.tamper_controller, 
                             from_weber=True, 
                             force_tamper_request=force_tamper_request)
        """set the cloned request"""
        log.debug_flow('Cloning request (duplicate).')
        t.request = weber.rrdb.rrs[rrid].request.clone()
        """add server to the path"""
        log.debug_flow(
            'Stripping server portion from request path (duplicate).')
        full_uri = weber.rrdb.rrs[rrid].server.uri.clone()
        full_uri.path = t.request.path.decode()
        t.request.path = full_uri.tostring().encode()
        log.debug_flow('Starting duplicate ConnectionThread.')
        """run the thread"""
        t.start()
        self.threads.append(t)
        """wait until new RRID is assigned"""
        while not t.rrid:
            time.sleep(0.1)
        return (t, t.rrid, t.request)

    def brute(self, rrid):
        """
        Duplicates request of given RRID and replaces the placeholders.
        This is done in ConnectionThreads (each taking care of portion
        of brute values).
        """
        if not weber.brute:
            log.err('Load your dictionary first with `bl` command.')
            return
        """guess number of threads to process this"""
        thread_count = 1
        if len(weber.brute[1]) > 256:
            thread_count = 8
        if len(weber.brute[1]) > 32:
            thread_count = 4
        elif len(weber.brute[1]) > 8:
            thread_count = 2
        """get standard set size to stuff incomplete sets"""
        normal_set_size = len(weber.brute[1][0])
        """
        separate brute dictionary into chunks for each thread,
        add stuffing if necessary
        """
        log.debug_flow(
            'Preparing dictionary chunks for brute-force (%d threads).' 
            % thread_count)
        brute_set_chunks = [[x if len(x) == normal_set_size 
                               else list(x) + [b''] * (normal_set_size - len(x))
                             for x in weber.brute[1][i::thread_count]]
                            for i in range(thread_count)]
        original_request = weber.rrdb.rrs[rrid].request
        """is in original_request at least one placeholder?"""
        placeholder_regex = '{0}[0-9]+{0}'.format(
            weber.config['brute.placeholder'].value)
        if not re.search(placeholder_regex.encode(), original_request.bytes()):
            log.err('No placeholder in selected request.')
            return
        """run threads"""
        for i in range(thread_count):
            log.debug_flow('Creating new ConnectionThread from Weber (brute).')
            t = ConnectionThread(None,
                                 self.tamper_controller,
                                 from_weber=True,
                                 brute_sets=brute_set_chunks[i])
            """set the cloned request"""
            log.debug_flow('Cloning request (brute).')
            t.request = original_request.clone()
            """add server to the path"""
            log.debug_flow('Stripping server portion of request path (brute).')
            full_uri = weber.rrdb.rrs[rrid].server.uri.clone()
            full_uri.path = t.request.path.decode()
            t.request.path = full_uri.tostring().encode()
            """run the thread"""
            log.debug_flow('Starting brute ConnectionThread.')
            t.start()
            self.threads.append(t)


class ConnectionThread(threading.Thread):
    """
    

    Attributes:
        downstream_socket () - socket from browser
        
    """
    def __init__(self, 
                 downstream_socket, 
                 tamper_controller, 
                 from_weber=False,
                 force_tamper_request=False,
                 brute_sets=None):
        """
        
        """
        threading.Thread.__init__(self)
        self.tamper_controller = tamper_controller
        self.downstream_socket = downstream_socket
        self.from_weber = from_weber
        self.force_tamper_request = force_tamper_request
        self.request = None
        self.response = None
        self.rrid = None # for one loop run only, but accesssed from functions
        self.terminate = False
        self.stopper = os.pipe() # to allow new request
        #self.server_id = None # TODO not necessary if self.server is used?
        self.server = None
        self.full_uri = None # for one loop run only, but accessed from functions
        self.upstream_socket = None
        self.connect_method = False
        self.protocol = weber.protocols['http']
        self.times = {} # for one loop run only, but accessed from functions
        self.waiting_for_request_forward = False # for `rqf`
        self.waiting_for_response_forward = False # for `rsf`
        self.brute_sets = brute_sets
        #self.watcher = Watcher(self.request, 'path', '/tmp/log.txt') # TODO for debugging
        #sys.settrace(self.watcher.trace_command)
    
    def send_continuation_signal(self):
        if self.stopper:
            os.write(self.stopper[1], b'1')
        #print('sending signal')
    
    def wait_for_continuation_signal(self):
        """

        """
        #print('waiting for signal')
        r, _, _ = select([self.stopper[0]], [], [])

    def stop(self):
        """
        
        """
        self.terminate = True
        """send continuation signal in case we are tampering"""
        self.send_continuation_signal()
    '''
    def add_request(self, request):
        """Adds request bytes manually.

        If the Request-Response pair is a copy, use known Request data.
        
        Args:
            request (): 
        """
        print('ADDING REQUEST MANUALLY!!!!!!!!!!!!!')
        self.request = request
        # TODO not fully implemented / tested
    '''

    def run(self):
        """

        """
        thread_started = datetime.now()
        first_run = True
        #keepalive = False if self.from_weber else True
        keepalive = False # new ConnectionThread for every request (excluding CONNECT and stuff)
        """send signal so first request can be processed"""
        #self.send_continuation_signal()
        
        request_raw = None
        if self.brute_sets:
            """set up raw request with placeholders"""
            request_raw = self.request.bytes()

        while keepalive or first_run or self.brute_sets:
            """wait for signal - cause previous request can be tampered"""
            #self.wait_for_continuation_signal()
            if self.terminate: break
            """reset times dictionary for new traffic"""
            self.times = {'thread_started': thread_started}
          
            if self.from_weber:
                """either duplicate or brute-force; store time"""
                self.times['request_received'] = datetime.now()
            else:
                """read request from socket if needed"""
                request_raw = ProxyLib.recvall(self.downstream_socket, 
                                               comment='downstream')
                #print(request_raw)
                if not request_raw:
                    break # TODO OK?
                self.times['request_received'] = datetime.now()
                log.debug_socket('Request received.')
            
            if self.terminate: break
            if request_raw:
                """convert to protocol-specific object if needed"""
                """new request or from brute template"""
                self.request = self.protocol.create_request(request_raw)
                if not self.request.integrity:
                    log.debug_protocol('Received request is invalid.')
                    self.send_response(b'HTTP/1.1 400 Bad Request\r\n\r\n!') #TODO all right?
                    #continue
                    break # OK cause 1 ConnectionThread deals with only 1 request

            """fill brute values if necessary"""
            if self.brute_sets:
                placeholder = weber.config['brute.placeholder'].value.encode()
                #if request_original:
                #    """use original with placeholders"""
                #    self.request.original = request_original
                #else:
                #    """first run -> store placeholder version"""
                #    request_original = self.request.original
                """replace each placeholder occurence of each index"""
                for i, value in enumerate(self.brute_sets[0]):
                    #print('replacing', value)
                    #print('before:', self.request.original[:50])
                    self.request.original = self.request.original.replace(
                        b'%s%d%s' % (placeholder, i, placeholder),
                        value)
                    #print('after:', self.request.original[:50])
                self.request.parse()
                #"""and fix path after that"""
                #self.request.path = self.request.path[
                #     self.request.path.find(
                #         b'/', 
                #         len(self.server.uri.scheme)+3):]
                self.brute_sets = self.brute_sets[1:]
            """provide Weber page with CA if path == /weber"""
            if self.request and self.request.path == b'/weber':
                self.send_response(b'HTTP/1.1 200 OK\r\n\r\nWeber page WORKS!')
                # TODO return CA and stuff
                break

            """get actual full_uri"""
            if self.connect_method:
                self.full_uri = self.server.uri.clone()
                try:
                    self.full_uri.path = self.request.path.decode()
                except UnicodeDecodeError:
                    log.err('Request with invalid bytes:')
                    log.tprint(self.request.path)
                    break
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
                    self.send_response(b'HTTP/1.1 418 I\'m a teapot\r\n\r\n') #TODO all right?
                    break
#                """create socket to server if None"""
#                self.connect_upstream()

                """was it CONNECT?"""
                if self.request.method == b'CONNECT':
                    """send confirmation response"""
                    self.connect_method = True
                    log.debug_flow('Accepting CONNECTion.')
                    self.send_response(b'HTTP/1.1 200 OK\r\n\r\n')
                    self.ssl_wrap('downstream')
#                """upgrade to SSL if necessary (probably always)"""
#                    if self.server.ssl:
#                        try:
#                            self.ssl_wrap()
#                        except Exception as e:
#                            log.err('Upgrading to SSL failed: %s' % str(e))
                    """and continue accepting requests"""
                    continue
                
#                """
#                Upgrade both sockets if SSL
#                CONNECT traffic is solved, this is only for first run 
#                of resend and brute
#                """
                if self.server.ssl and first_run:
                    self.ssl_wrap('downstream')
#                    try:
#                        self.ssl_wrap()
#                    except Exception as e:
#                        log.err('Upgrading to SSL failed: %s' % str(e))
#                        continue
#                """create socket to server if None"""
                    
            if not self.connect_method:
                """ not connect -> remove server from req path"""
                self.request.path = self.request.path[
                     self.request.path.find(
                         b'/', 
                         len(self.server.uri.scheme)+3):]

            """request and server are done, time to play with it"""
            self.rrid = weber.rrdb.get_new_rrid()
            weber.rrdb.add_request(self.rrid, 
                                   self.request, 
                                   self.server, 
                                   self.times)
            if self.terminate: break
            """run pre_tamper operations"""        
            self.request.pre_tamper()
            """tamper/forward request"""
            self.try_forward_tamper()
            """terminate loop - no keepalive"""  # TODO is that normal?
            first_run = False
            """end of main loop"""

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
            
    def try_forward_tamper(self):
        """
        Because in some cases (`rqrm`) request is forcefully tampered,
        but after changes, we also want to respect tamper settings.
        """
        if (self.tamper_controller.ask_for_request_tamper() 
                or self.force_tamper_request): 
            log.debug_tampering('Request is tampered.')
            self.times['request_tampered'] = datetime.now()
            self.waiting_for_request_forward = True
            """tampering; print overview if appropriate"""
            if (not self.force_tamper_request and positive(
                weber.config['interaction.realtime_overview'].value)):
                log.tprint(' '.join(weber.rrdb.overview(
                    [str(self.rrid)],
                    header=False)))
        else:
            log.debug_tampering('Forwarding request without tampering.')
            self.continue_forwarding()
        """
        following parts are in continue_forwarding method,
        as those can happen much later.
        """

    def continue_forwarding(self):
        """

        """
        self.waiting_for_request_forward = False
        if not self.request:
            log.err('Tried to forward non-existent request.')
            return
        self.request.post_tamper()
        self.server.get_rps_approval() # sleep for RPS limiting
        if self.terminate: return
        self.times['request_forwarded'] = datetime.now()
        response_raw = self.forward(self.request.bytes())
        if not response_raw:
            log.err('Response is empty! You can try to increase '
                    'proxy.socket_timeout value.')
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
        if self.tamper_controller.ask_for_response_tamper():
            log.debug_tampering('Response is tampered.')
            self.times['response_tampered'] = datetime.now()
            self.waiting_for_response_forward = True
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
        self.waiting_for_response_forward = False
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
        """

        """
        try:
            if not self.upstream_socket:
                self.connect_upstream()
                if self.server.ssl:
                    self.ssl_wrap('upstream')
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
        except:
            log.err('No upstream socket - cannot forward.')
            traceback.print_exc()
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
    
    def connect_upstream(self):
        """

        """
        if not self.upstream_socket:
            log.debug_socket('Creating upstream socket.')
            self.upstream_socket = socket.socket(socket.AF_INET, 
                                                 socket.SOCK_STREAM)
            try:
                self.upstream_socket.connect((self.server.uri.domain,
                                              self.server.uri.port))
            except Exception as e:
                log.err('Upstream connect error for %s: %s' 
                        % (self.full_uri.tostring(), str(e)))

    def ssl_wrap(self, direction):
        """


        Run this in try-catch.
        """
        if direction == 'downstream' and self.downstream_socket:
            log.debug_socket('Upgrading downstream socket to SSL.')
            self.downstream_socket.setblocking(True) # TODO fails when `rqm` ssl stuff...
            self.downstream_socket = ssl.wrap_socket(
                self.downstream_socket, 
                certfile=self.server.certificate_path,
                keyfile=self.server.certificate_key_path,
                #do_handshake_on_connect=True,
                server_side=True)
        if direction == 'upstream' and self.upstream_socket:
            log.debug_socket('Upgrading upstream socket to SSL.')
            self.upstream_socket = ssl.wrap_socket(self.upstream_socket)

