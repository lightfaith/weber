#!/usr/bin/env python3
"""
General-purpose stuff is defined here.
"""
from source import log
from source.baselib import *
import io
import os
import pdb
import signal
import subprocess
import sys
import time
import traceback
import difflib

import gzip
import zlib  # for deflate
from io import StringIO

import brotli

#from gzip import GzipFile
#from source import weber
from source import log


def exit_program(signal, frame):
    """immediate termination due to -h, bad parameter or bind() fail"""
    if signal == -1:
        sys.exit(0)

    log.newline()  # newline

    log.info('Killing all the threads...')

    # stop the scheduler (will stop all threads)
    from source import weber
    weber.proxy.stop()
    #counter = 0
    while weber.proxy.is_alive():
        time.sleep(0.1)
    #    counter += 1
    #    if counter == 50:
    #        log.info('Force termination.')
    #        break
    sys.exit(0 if signal is None else 1)


# run exit program on SIGINT
signal.signal(signal.SIGINT, exit_program)


def exception(message, *args):
    log.err('Exception occured!')
    log.err('Cause:', message)
    traceback.print_exc()
    for arg in args:
        print(arg)
    log.err('-- END OF EXCEPTION --')


def reload_config():
    """

    """
    from source import weber
    """read lines from conf file"""
    log.info('Loading config file...')
    with open(os.path.join(os.path.dirname(sys.argv[0]), 'files/weber.conf'),
              'r') as f:
        for line in f.readlines():
            line = line.strip()
            """skip empty lines and comments"""
            if len(line) == 0 or line.startswith('#'):
                continue
            """get keys and values"""
            k, _, v = line.partition('=')
            log.debug_config('  line: \'%s\'' % (line))
            k = k.strip()
            v = v.strip()
            """save values"""
            if k in weber.config:
                """existing value, use property to save it"""
                weber.config[k].value = v
            else:
                """proprietary value, add new as str"""
                weber.config['@'+k] = weber.Option(v, str)
            '''    
            if k in weber.config.keys():
                if weber.config[k][1] in (bool, int, float):
                    if weber.config[k][1] == bool:
                        v = positive(v)
                    weber.config[k] = (weber.config[k][1](v), weber.config[k][1])
                else:
                    weber.config[k] = (v, str)
            '''
            log.info('  %s = %s' % (k, v))
            log.debug_config('  parsed: %s = %s (%s)' % (k, v, str(type(v))))


def get_color_from_extension(path):
    """

    """
    color = log.COLOR_NONE
    if path.endswith((b'/',
                      b'.htm',
                      b'.html',
                      b'.php',
                      b'.xhtml',
                      b'.aspx')):
        color = log.MIMECOLOR_HTML
    elif path.endswith((b'.jpg',
                        b'.svg',
                        b'.png',
                        b'.gif',
                        b'.ico')):
        color = log.MIMECOLOR_IMAGE
    elif path.endswith((b'.mp3',
                        b'.ogg',
                        b'.mp4',
                        b'.wav')):
        color = log.MIMECOLOR_MULTIMEDIA
    elif path.endswith((b'.js',
                        b'.vbs',
                        b'.swf')):
        color = log.MIMECOLOR_SCRIPT
    elif path.endswith((b'.css',)):
        color = log.MIMECOLOR_CSS
    elif path.endswith((b'.pdf',
                        b'.doc',
                        b'.docx',
                        b'.xls',
                        b'.xlsx',
                        b'.ppt',
                        b'.pptx',
                        b'.pps',
                        b'.ppsx')):
        color = log.MIMECOLOR_DOCUMENT
    elif path.endswith((b'.txt',)):
        color = log.MIMECOLOR_PLAINTEXT
    elif path.endswith((b'.zip',
                        b'.7z',
                        b'.rar',
                        b'.gz',
                        b'.bz2',
                        b'.jar',
                        b'.bin',
                        b'.iso')):
        color = log.MIMECOLOR_ARCHIVE
    return color


def get_color_from_content_type(content_type=None):
    """

    """
    color = log.COLOR_NONE
    if content_type is None:
        return color
    if content_type.startswith(b'text/'):  # text stuff, usually html
        color = log.MIMECOLOR_HTML
        ct_part = content_type[5:]
        if ct_part.startswith(b'css'):  # css
            color = log.MIMECOLOR_CSS
        elif ct_part.startswith(b'javascript'):  # javascript
            color = log.MIMECOLOR_SCRIPT
        elif ct_part.startswith(b'plain'):  # plaintext
            color = log.MIMECOLOR_PLAINTEXT
        elif ct_part.startswith(b'xml'):  # data transfer
            color = log.MIMECOLOR_DATATRANSFER
    elif content_type.startswith(b'application/'):  # various types
        ct_part = content_type[12:]
        if ct_part.startswith((b'xhtml')):
            color = log.MIMECOLOR_HTML
        elif ct_part.startswith((b'javascript',
                                 b'x-javascript',
                                 b'x-shockwave')):  # scripts
            color = log.MIMECOLOR_SCRIPT
        elif ct_part.startswith(b'octet-stream'):  # binary
            color = log.MIMECOLOR_BINARY
        elif ct_part.startswith((b'x-bzip',
                                 b'x-rar-compressed',
                                 b'x-tar',
                                 b'x-7z-compressed',
                                 b'zip')):  # archives
            color = log.MIMECOLOR_ARCHIVE
        elif ct_part.startswith((b'msword',
                                 b'vnd.ms-powerpoint',
                                 b'vnd.ms-excel',
                                 b'vnd.openxmlformats-officedocument',
                                 b'vnd.oasis.opendocument',
                                 b'pdf')):  # documents
            color = log.MIMECOLOR_DOCUMENT
        elif ct_part.startswith((b'ogg')):  # ogg
            color = log.MIMECOLOR_MULTIMEDIA
        elif ct_part.startswith((b'json', b'xml')):  # data transfer
            color = log.MIMECOLOR_DATATRANSFER
        elif ct_part.startswith((b'postscript')):  # image
            color = log.MIMECOLOR_IMAGE

    elif content_type.startswith(b'image/'):  # images
        color = log.MIMECOLOR_IMAGE

    elif content_type.startswith((b'audio/',
                                  b'video/')):  # multimedia
        color = log.MIMECOLOR_MULTIMEDIA

    elif content_type.startswith((b'message/')):  # message
        color = log.MIMECOLOR_MESSAGE
    return color


def is_content_type_text(content_type):
    """

    """
    return (get_color_from_content_type(content_type)
            in (log.MIMECOLOR_PLAINTEXT,
                log.MIMECOLOR_HTML,
                log.MIMECOLOR_SCRIPT,
                log.MIMECOLOR_CSS,
                log.MIMECOLOR_DATATRANSFER,
                log.MIMECOLOR_MESSAGE))


def get_colored_printable(b):
    """

    """
    color = log.COLOR_BROWN
    if b in (0x9, 0xa, 0xd):
        color = log.COLOR_DARK_GREEN
        b = ord('.')
    elif b < 0x20 or b >= 0x7f:
        color = log.COLOR_NONE
        b = ord('.')
    return color+chr(b)+log.COLOR_NONE


def get_colored_printable_hex(b):
    """

    """
    color = log.COLOR_NONE
    if b >= 0x20 and b < 0x7f:
        color = log.COLOR_BROWN
    elif b in (0x9, 0xa, 0xd):
        color = log.COLOR_DARK_GREEN
    return color + '%02x' % b + log.COLOR_NONE


def hexdump(data):
    """
    Prints data as with `hexdump -C` command.
    """
    result = []
    line_count = 0
    for chunk in chunks(data, 16):
        hexa = ' '.join(''.join(get_colored_printable_hex(b) for b in byte)
                        for byte in [chunk[start:start+2]
                                     for start in range(0, 16, 2)])

        """add none with coloring - for layout"""
        if len(hexa) < 199:
            hexa += (log.COLOR_NONE+'  '+log.COLOR_NONE)*(16-len(chunk))

        result.append(log.COLOR_DARK_GREEN
                      + '%08x' % (line_count*16)
                      + log.COLOR_NONE
                      + '  %-160s' % (hexa)
                      + ' |'
                      + ''.join(get_colored_printable(b) for b in chunk) + '|')
        line_count += 1
    return result


def create_folders_from_uri(root, uri):
    """
    Args:
        uri (str) - URI of the server + path in str format
    """
    uri_path = uri.replace(':', '_').replace('//', '__')
    # only folder? create fake index.html
    if uri_path.endswith('/'):
        uri_path += 'index.html'

    file_path = os.path.join(root, uri_path)
    log.debug_flow('  File will be %s.' % file_path)
    try:
        os.makedirs(file_path[:file_path.rfind('/')], exist_ok=True)
    except:
        traceback.print_exc()
        log.err('Cannot create folder structure.')
    return file_path


def encode_data(data, encoding):
    """
    Encodes data into the specified encoding used in HTTP.

    Args:
        data (bytes) - data to encode (typically response data)
        encoding (str) - encoding type (br, compress, deflate, 
                                        gzip, identity)
    Returns:
        encoded data (bytes)
    """
    if encoding == 'br':
        """br encoding"""
        return brotli.compress(data)
    elif encoding == 'compress':
        """compress encoding"""
        # TODO not tested
        print('encoding compress (lzw)')
        return lzw_compress(data)
    elif encoding == 'deflate':
        """deflate encoding"""
        # TODO not tested
        print('encoding deflate')
        return zlib.compress(data)
    elif encoding == 'gzip':
        """gzip encoding"""
        return gzip.compress(data)
    elif encoding == 'identity':
        """identity encoding - no compression at all"""
        return data
    else:
        log.err('Unknown encoding \'%s\'' % encoding)
        return b''


def decode_data(data, encoding):
    """
    Decodes data from the specified encoding used in HTTP.

    Args:
        data (bytes) - data to encode (typically response data)
        encoding (str) - encoding type (br, compress, deflate, 
                                        gzip, identity)
    Returns:
        decoded data (bytes)
    """
    if encoding == 'br':
        """br encoding"""
        return brotli.decompress(data)
    elif encoding == 'compress':
        """compress encoding"""
        print('decoding compress (lzw)')
        return lzw_decompress(data)
        # TODO not tested
    elif encoding == 'deflate':
        """deflate encoding"""
        # TODO not tested
        print('decoding deflate')
        return zlib.decompress(data)
    elif encoding == 'gzip':
        """gzip encoding"""
        return gzip.decompress(data)
    elif encoding == 'identity':
        """identity encoding - no compression at all"""
        return data
    else:
        log.err('Unknown encoding \'%s\'' % encoding)
        return b''


def lzw_compress(data):
    """
    Implementation of LZW compression, used in 'compress' 
    Content-Encoding method in HTTP.
    Source: https://rosettacode.org/wiki/LZW_compression#Python

    Args:
        data (bytes): normal data
    Returns:
        compressed data (bytes)
    """
    dict_size = 256
    dictionary = {chr(i): i for i in range(dict_size)}
    w = ""
    result = []
    for c in data:
        wc = w + c
        if wc in dictionary:
            w = wc
        else:
            result.append(bytes([dictionary[w]]))
            dictionary[wc] = dict_size
            dict_size += 1
            w = c
    if w:
        result.append(bytes([dictionary[w]]))
    return b''.join(result)


def lzw_decompress(data):
    """
    Implementation of LZW decompression, used in 'compress' 
    Content-Encoding method in HTTP.
    Source: https://rosettacode.org/wiki/LZW_compression#Python

    Args:
        data (bytes): compressed data
    Returns:
        decompressed data (bytes)
    """
    dict_size = 256
    dictionary = {i: chr(i) for i in range(dict_size)}
    result = StringIO()
    w = chr(data.pop(0))
    result.write(w)
    for c in data:
        if c in dictionary.keys():
            entry = dictionary[c]
        elif c == dict_size:
            entry = w + w[0]
        else:
            raise ValueError('Bad LZW compression.')
        result.write(entry)
        dictionary[dict_size] = w + entry[0]
        dict_size += 1
    return result.getvalue()


# --
