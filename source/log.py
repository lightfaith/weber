#!/usr/bin/env python3
"""
Print and logging stuff is here.
"""

import threading
from source.lib import positive
from source.weber import config


"""
Colors
"""
COLOR_NONE        = '\033[00m'
COLOR_BOLD        = "\033[01m"

COLOR_BLACK       = '\033[30m'
COLOR_DARK_RED    = '\033[31m'
COLOR_DARK_GREEN  = '\033[32m'
COLOR_BROWN       = '\033[33m'
COLOR_DARK_BLUE   = '\033[34m'
COLOR_DARK_PURPLE = '\033[35m'
COLOR_DARK_CYAN   = '\033[36m'
COLOR_GREY        = '\033[37m'

COLOR_DARK_GREY   = '\033[90m'
COLOR_RED         = '\033[91m'
COLOR_GREEN       = '\033[92m'
COLOR_YELLOW      = '\033[93m'
COLOR_BLUE        = '\033[94m'
COLOR_PURPLE      = '\033[95m'
COLOR_CYAN        = '\033[96m'
COLOR_WHITE       = '\033[97m'

"""
Colors for MIME types
"""
MIMECOLOR_PLAINTEXT = COLOR_GREEN
MIMECOLOR_HTML = COLOR_GREY
MIMECOLOR_SCRIPT = COLOR_BLUE
MIMECOLOR_CSS = COLOR_DARK_PURPLE
MIMECOLOR_IMAGE = COLOR_PURPLE
MIMECOLOR_MULTIMEDIA = COLOR_CYAN
MIMECOLOR_ARCHIVE = COLOR_BROWN
MIMECOLOR_BINARY = COLOR_DARK_GREY
MIMECOLOR_DATATRANSFER = COLOR_YELLOW
MIMECOLOR_DOCUMENT = COLOR_GREEN
MIMECOLOR_MESSAGE = COLOR_DARK_BLUE

prompt = COLOR_PURPLE+COLOR_BOLD+' )> '+COLOR_NONE

loglock = threading.Lock()

"""
Thread-safe print
"""
def tprint(string='', color=COLOR_NONE, new_line=True, stdout=True):
    lines = []
    lines.append(color+string+COLOR_NONE)
    if stdout:
        with loglock:
            for line in lines:
                print(line, end=('\n' if new_line else ''))
    return lines

def newline(stdout=True):
    lines = []
    lines.append('')
    if stdout:
        with loglock:
            for line in lines:
                print(line)
    return lines

"""
OK, INFO, WARN, ERR, QUESTION
"""
def show_marked(c, color='', *args, new_line=True, stdout=True):
    lines = []
    #lines.append('%s%s%s%s%s%s' % (color, COLOR_BOLD, c, COLOR_NONE, str(string),('\n' if newline else '')))
    lines.append('%s%s%s%s%s' % (color, COLOR_BOLD, c, COLOR_NONE, ' '.join(str(arg) for arg in args)))
    if stdout:
        with loglock:
            for line in lines:
                print(line, end=('\n' if new_line else ''))
    return lines

def ok(*args, new_line=True, stdout=True):
    return show_marked('[+] ', COLOR_GREEN, *args, new_line=newline, stdout=stdout)

def info(*args, new_line=True, stdout=True):
    return show_marked('[.] ', COLOR_BLUE, *args, new_line=newline, stdout=stdout)
    
def warn(*args, new_line=True, stdout=True):
    return show_marked('[!] ', COLOR_YELLOW, *args, new_line=newline, stdout=stdout)
    
def err(*args, new_line=True, stdout=True):
    return show_marked('[-] ', COLOR_RED, *args, new_line=newline, stdout=stdout)
 
def question(*args, new_line=True, stdout=True):
    return show_marked('[?] ', COLOR_CYAN, *args, new_line=newline, stdout=stdout)


"""
Debug functions
"""
def debug_command(*args):
    if positive(config['debug.command'].value):
        show_marked('cmd.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)

def debug_config(*args):
    if positive(config['debug.config'].value):
        show_marked('cnf.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)

def debug_mapping(*args):
    if positive(config['debug.mapping'].value):
        show_marked('map.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)

def debug_parsing(*args):
    if positive(config['debug.parsing'].value):
        show_marked('prs.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)

def debug_server(*args):
    if positive(config['debug.server'].value):
        show_marked('srv.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)

def debug_socket(*args):
    if positive(config['debug.socket'].value):
        show_marked('sck.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)

def debug_chunks(*args):
    if positive(config['debug.chunks'].value):
        show_marked('cnk.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)

def debug_tampering(*args):
    if positive(config['debug.tampering'].value):
        show_marked('tpr.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)

def debug_analysis(*args):
    if positive(config['debug.analysis'].value):
        show_marked('anl.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)

def debug_protocol(*args):
    if positive(config['debug.protocol'].value):
        show_marked('prt.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)

def debug_flow(*args):
    if positive(config['debug.flow'].value):
        show_marked('flw.', COLOR_DARK_GREY, COLOR_DARK_GREY+' '.join(str(arg) for arg in args)+COLOR_NONE)


