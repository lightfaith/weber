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

