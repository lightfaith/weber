#!/usr/bin/env python3
"""
General-purpose stuff is defined here.
"""
import sys, signal, io, time
from gzip import GzipFile
from source import weber
from source import log

def positive(x):
    if type(x) == str:
        x = x.lower()
    if x in ['yes', 'y', '+', '1', 1, 'true', 't', True]:
        return True
    return False

def negative(x):
    if type(x) == str:
        x = x.lower()
    if x in ['no', 'n', '-', '0', 0, 'false', 'f', False]:
        return True
    return False

def quitstring(x):
    if type(x) != str:
        return False
    x = x.lower()
    if x in ['quit', 'exit', 'q', 'end', ':wq']:
        return True
    return False

def exit_program(signal, frame):
    if signal == -1: # immediate termination due to -h or bad parameter
        sys.exit(0)

    log.newline() # newline

    log.info('Killing all the threads...')

    # stop the scheduler (will stop all threads)
    weber.proxy.stop()
    while weber.proxy.is_alive():
        time.sleep(0.1)
    sys.exit(0 if signal is None else 1)

# run exit program on SIGINT
signal.signal(signal.SIGINT, exit_program)

"""
# for some reason does not work with responses: [-] Not a gzipped file (b'7a')
def gzip(i): # bytes -> gzip
    o = io.BytesIO()
    with GzipFile(fileobj=o, mode='w') as g:
        g.write(i)
    return o.getvalue()
    
def gunzip(data): # gzip -> bytes
    i = io.BytesIO()
    i.write(data)
    i.seek(0)
    with GzipFile(fileobj=i,mode='rb') as g:
       o = g.read()
    return o
"""

def find_between(data, startbytes, endbytes, startpos=0, endpos=0, inner=False):
    # this function goes through data[startpos:endpos] and locates substrings 'startbytes.*endbytes'
    # returns list of (absolute_position, match_string)
    # inner specifies whether startbytes and endbytes should be included in match_string
    if endpos == 0:
        endpos = len(data)
    result = []
    while True:
        try:
            offset = data.index(startbytes, startpos)
            start = offset+(len(startbytes) if inner else 0)
            end = data.index(endbytes, start)+(0 if inner else len(endbytes))
            if end>endpos: # behind the endpos limit?
                break
            result.append((offset, data[start:end]))
            # prepare for next search
            startpos = end
        except ValueError: # out of bounds (no more matches)?
            break
    return result


def get_color_from_content_type(content_type=None):
    color = log.COLOR_NONE
    if content_type is None:
        return color
    if content_type.startswith(b'text/'): # text stuff, usually html
        color = log.MIMECOLOR_HTML
        ct_part = content_type[5:]
        if ct_part.startswith(b'css'): # css
            color = log.MIMECOLOR_CSS
        elif ct_part.startswith(b'javascript'): # javascript
            color = log.MIMECOLOR_SCRIPT
        elif ct_part.startswith(b'plain'): # plaintext
            color = log.MIMECOLOR_PLAINTEXT
        elif ct_part.startswith(b'xml'): # data transfer
            color = log.MIMECOLOR_DATATRANSFER
    elif content_type.startswith(b'application/'): # various types
        ct_part = content_type[12:]
        if ct_part.startswith((b'xhtml')):
            color = log.MIMECOLOR_HTML
        elif ct_part.startswith((b'javascript', b'x-javascript', b'x-shockwave')): # scripts
            color = log.MIMECOLOR_SCRIPT
        elif ct_part.startswith(b'octet-stream'): # binary
            color = log.MIMECOLOR_BINARY
        elif ct_part.startswith((b'x-bzip', b'x-rar-compressed', b'x-tar', b'x-7z-compressed', b'zip')): # archives
            color = log.MIMECOLOR_ARCHIVE
        elif ct_part.startswith((b'msword', b'vnd.ms-powerpoint', b'vnd.ms-excel', b'vnd.openxmlformats-officedocument', b'vnd.oasis.opendocument', b'pdf')): # documents
            color = log.MIMECOLOR_DOCUMENT
        elif ct_part.startswith((b'ogg')): # ogg
            color = log.MIMECOLOR_MULTIMEDIA
        elif ct_part.startswith((b'json', b'xml')): # data transfer
            color = log.MIMECOLOR_DATATRANSFER
        elif ct_part.startswith((b'postscript')): # image
            color = log.MIMECOLOR_IMAGE

    elif content_type.startswith(b'image/'): # images
        color = log.MIMECOLOR_IMAGE

    elif content_type.startswith((b'audio/', b'video/')): # multimedia
        color = log.MIMECOLOR_MULTIMEDIA
    return color
 

def is_content_type_text(content_type):
    return get_color_from_content_type(content_type) in (log.MIMECOLOR_PLAINTEXT, log.MIMECOLOR_HTML, log.MIMECOLOR_SCRIPT, log.MIMECOLOR_CSS, log.MIMECOLOR_DATATRANSFER)
