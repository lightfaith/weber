#!/usr/bin/env python3
"""
General-purpose stuff is defined here.
"""
import os, sys, signal, io, time
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

def reload_config():
    log.info('Loading config file...')
    # read lines from conf file
    with open(os.path.join(os.path.dirname(sys.argv[0]), 'weber.conf'), 'r') as f:
        for line in f.readlines():
            line = line.strip()
            # skip empty and comments
            if len(line) == 0 or line.startswith('#'):
                continue
            # get keys and values
            k, _, v = line.partition('=')
            log.debug_config('  line: \'%s\'' % (line))
            k = k.strip()
            v = v.strip()
            # cast to correct type and save into weber.config
            if k in weber.config.keys():
                if weber.config[k][1] in (bool, int, float):
                    if weber.config[k][1] == bool:
                        v = positive(v)
                    weber.config[k] = (weber.config[k][1](v), weber.config[k][1])
                else:
                    weber.config[k] = (v, str)
            log.info('  %s = %s' % (k, v))
            log.debug_config('  parsed: %s = %s (%s)' % (k, v, str(type(v))))



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

def get_color_from_extension(path):
    color = log.COLOR_NONE
    if path.endswith((b'/', b'.htm', b'.html', b'.php', b'.xhtml', b'.aspx')):
        color = log.MIMECOLOR_HTML
    elif path.endswith((b'.jpg', b'.svg', b'.png', b'.gif', b'.ico')):
        color = log.MIMECOLOR_IMAGE
    elif path.endswith((b'.mp3', b'.ogg', b'.mp4', b'.wav')):
        color = log.MIMECOLOR_MULTIMEDIA
    elif path.endswith((b'.js', b'.vbs', b'.swf')):
        color = log.MIMECOLOR_SCRIPT
    elif path.endswith((b'.css')):
        color = log.MIMECOLOR_CSS
    elif path.endswith((b'.pdf', b'.doc', b'.docx', b'.xls', b'.xlsx', b'.ppt', b'.pptx', b'.pps', b'.ppsx')):
        color = log.MIMECOLOR_DOCUMENT
    elif path.endswith(b'.txt'):
        color = log.MIMECOLOR_PLAINTEXT
    elif path.endswith((b'.zip', b'.7z', b'.rar', b'.gz', b'.bz2', b'.jar', b'.bin', b'.iso')):
        color = log.MIMECOLOR_ARCHIVE
    return color


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
    
    elif content_type.startswith((b'message/')): # multimedia
        color = log.MIMECOLOR_MESSAGE
    return color
 

def is_content_type_text(content_type):
    return get_color_from_content_type(content_type) in (log.MIMECOLOR_PLAINTEXT, log.MIMECOLOR_HTML, log.MIMECOLOR_SCRIPT, log.MIMECOLOR_CSS, log.MIMECOLOR_DATATRANSFER, log.MIMECOLOR_MESSAGE)


def split_escaped(string, delimiter):
    if len(delimiter) != 1:
        raise ValueError('Invalid delimiter: ' + delimiter)
    ln = len(string)
    i = 0
    j = 0
    while j < ln:
        if string[j] == '\\':
            if j + 1 >= ln:
                yield string[i:j].replace('\\', '')
                return
            j += 1
        elif string[j] == delimiter:
            yield string[i:j].replace('\\', '')
            i = j + 1
        j += 1
    yield string[i:j].replace('\\', '')

chunks = lambda data,size: [data[x:x+size] for x in range(0, len(data), size)]

def print_colored_printable(b):
    if b>=0x20 and b<0x7f:
        return log.COLOR_BROWN+chr(b)+log.COLOR_NONE
    elif b in (0x9, 0xa, 0xd):
        return log.COLOR_DARK_GREEN+'.'+log.COLOR_NONE
    return '.'

def hexdump(data):
    # prints data as with `hexdump -C` command
    result = []
    line_count = 0
    for chunk in chunks(data, 16):
        hexa = ' '.join(''.join('%02x' % (b) for b in byte) for byte in [chunk[start:start+2] for start in range(0, 16, 2)])
        result.append(log.COLOR_DARK_GREEN + '%08x' % (line_count*16) + log.COLOR_NONE +'  %-40s' % (hexa) + ' |' + ''.join(print_colored_printable(b) for b in chunk) + '|')
        line_count += 1
    #if result: # if request matches and response not, 2 headers are printed...
    #    result.insert(0, '{grepignore}-offset-   0 1  2 3  4 5  6 7  8 9  A B  C D  E F   0123456789ABCDEF')
    
    return result

    

