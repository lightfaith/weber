#!/usr/bin/env python3
"""
Commands and config methods are implemented here.
"""

from source import weber
from source import lib
from source import log
from source.structures import RRDB
import os, sys, re, traceback

"""
Load configuration
"""
def reload_config():
    log.info('Loading config file...')
    with open(os.path.join(os.path.dirname(sys.argv[0]), 'config'), 'r') as f:
        for line in f.readlines():
            line = line.strip()
            if len(line) == 0 or line.startswith('#'):
                continue
            k, _, v = line.partition('=')
            log.debug_config('  line: \'%s\'' % (line))
            k = k.strip()
            v = v.strip()
            if v.isdigit():
                v = int(v)
            if lib.positive(v):
                v = True
            if lib.negative(v):
                v = False
            weber.config[k] = v
            log.info('  %s = %s' % (k, v))
            log.debug_config('  parsed: %s = %s (%s)' % (k, v, str(type(v))))
    #log.ok('Go!')



"""
Universal class for commands.
"""
class Command():
    def __init__(self, command, apropos, description, function):
        self.command = command
        self.apropos = apropos
        self.description = description
        self.function = function

    def run(self, *args):
        return self.function(*args)

    def __repr__(self):
        return 'Command(%s)' % (self.command)

    def __str__(self):
        return 'Command(%s)' % (self.command)


"""
Function to add new command
"""
def add_command(command):
    weber.commands[command.command.partition(' ')[0]] = command


"""
Function to run commands, apply filters etc.
"""
def run_command(fullcommand):
    log.debug_command('  Fullcmd: \'%s\'' % (fullcommand))
    command, _, grep = fullcommand.partition('~')
    # only help?
    if command.endswith('?'):
        lines = []
        for k, v in weber.commands.items():
            length = 40
            if k.startswith(command[:-1]) and len(k)-len(command[:-1])<=1:
                # do colors
                cmd, _, args = v.command.partition(' ')
                # question mark after command?
                more = ''
                if len([x for x in weber.commands.keys() if x.startswith(cmd)])>1:
                    length += len(log.COLOR_BROWN)+len(log.COLOR_NONE)
                    more = log.COLOR_BROWN+'[?]'+log.COLOR_NONE
                command_colored = '%s%s %s%s%s' % (cmd, more, log.COLOR_BROWN, args, log.COLOR_NONE)
                apropos_colored = '%s%s%s' % (log.COLOR_DARK_GREEN, v.apropos, log.COLOR_NONE)
                lines.append('    %-*s %s' % (length, command_colored, apropos_colored))
    else:
        try:
            command, *args = command.split(' ')
            log.debug_command('  Command: \'%s\'' % (command))
            log.debug_command('  Args:    %s' % (str(args)))
            lines = weber.commands[command].run(*args)
        except Exception as e:
            log.err('Cannot execute command \''+command+'\': '+str(e)+'.')
            log.err('See traceback:')
            traceback.print_exc()
            return
    #print(lines)
    log.tprint('\n'.join([line for line in lines if grep in re.sub(r'\[[0-9]*m', '', line)]))


"""
TEST COMMANDS
"""
def test_function(*args):
    #d = xmltodict.parse(weber.rrdb.rrs[1].response.data)
    #print(d)
    #d['html']['body']['center']['h1'] = 'Welcome to modified nginx!'
    #xml = xmltodict.unparse({'body': d['html']['body']})
    #print(xml)
    print(weber.rrdb.rrs[1].response.find_tags('html'))
    
    return []
add_command(Command('test', 'prints test message', '', test_function))
add_command(Command('testa', 'prints test equation', '', lambda *args: ['1+1=2']))


"""
PRINT COMMANDS
"""
add_command(Command('p', 'print', '', lambda *_: []))

add_command(Command('pc [<rrid>[:<rrid>]]', 'print cookies', '', lambda: []))

# pf
def pf_function(*args):
    result = []
    for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
        tmpresult = []
        tmpresult.append('%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE))
        for f in rr.response.find_tags('form', form='xml'):
            tmpresult.append(f)
        if len(tmpresult)>1:
            result += tmpresult
    return result
add_command(Command('pf [<rrid>[:<rrid>]]', 'print forms', '', pf_function))
add_command(Command('pl [<rrid>[:<rrid>]]', 'print links', '', lambda: []))
add_command(Command('pm', 'print URI mapping', '', lambda *args: ['%s: %s' % (k, v) for k, v in weber.mapping.l_r.items()]))
add_command(Command('pn [<rrid>[:<rrid>]]', 'print comments', '', lambda: []))

# pp
def pp_function(*args):
    result = []
    for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
        tmpresult = []
        tmpresult.append('%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE))
        # TODO
        tmpresult.append(str(rr.request.parameters))
        if len(tmpresult)>1:
            result += tmpresult
    return result        
add_command(Command('pp [<rrid>[:<rrid>]]', 'print parameters', '', pp_function))

# pr
def pr_function(*args):
    #start, end = RRDB.get_interval(args, 1, len(weber.rrdb.rrs.items()))
    return weber.rrdb.overview(args)
add_command(Command('pr [<rrid>[:<rrid>]]', 'print request-response pairs', '', pr_function))

# prx
def prx_function(*args, mask=0xf): # print detailed headers/data/both of desired requests/responses/both
    showrequest = bool(mask & 0x8)
    showresponse = bool(mask & 0x4)
    showheaders = bool(mask & 0x2)
    showdata = bool(mask & 0x1)
    result = []

    for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
        tmpresult = ['%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE)]
        # deal with requests
        if showrequest:
            tmpresult += rr.request.lines(headers=showheaders, data=showdata)
        # deal with responses
        if showresponse:
            tmpresult += rr.response.lines(headers=showheaders, data=showdata)
        # add gathered to the final result
        if len([x for x in tmpresult if len(x.strip())>0])>1:
            result += tmpresult
    return result
add_command(Command('pra [<rrid>[:<rrid>]]', 'print requests and responses verbose', '', lambda *args: prx_function(*args, mask=0xf)))
add_command(Command('prh [<rrid>[:<rrid>]]', 'print request and response headers', '', lambda *args: prx_function(*args, mask=0xe)))
add_command(Command('prd [<rrid>[:<rrid>]]', 'print request and response data', '', lambda *args: prx_function(*args, mask=0xd)))
add_command(Command('prq [<rrid>[:<rrid>]]', 'print requests verbose', '', lambda *args: prx_function(*args, mask=0xb)))
add_command(Command('prqh [<rrid>[:<rrid>]]', 'print request headers', '', lambda *args: prx_function(*args, mask=0xa)))
add_command(Command('prqd [<rrid>[:<rrid>]]', 'print request data', '', lambda *args: prx_function(*args, mask=0x9)))
add_command(Command('prs [<rrid>[:<rrid>]]', 'print responses verbose', '', lambda *args: prx_function(*args, mask=0x7)))
add_command(Command('prsh [<rrid>[:<rrid>]]', 'print response headers', '', lambda *args: prx_function(*args, mask=0x6)))
add_command(Command('prsd [<rrid>[:<rrid>]]', 'print response data', '', lambda *args: prx_function(*args, mask=0x5)))

"""
Quit
"""
add_command(Command('q', 'quit', '', lambda *_: [])) # solved in weber


#add_command(Command('', '', '',))
