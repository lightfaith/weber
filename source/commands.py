#!/usr/bin/env python3
"""
Commands and config methods are implemented here.
"""

from source import weber
from source import lib
from source import log
from source.structures import RRDB
import os, sys, re, traceback
from bs4 import Comment

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
    constants = {
        'link_tags': [('a', 'href', None), ('form', 'action', None), ('frame', 'src', None), ('img', 'src', None), ('script', 'src', None)] # TODO more?
    }

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
            # TODO detailed help for exact match
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
    """
    Lines can be:
        a list of strings:
            every line matching grep expression or starting with '{grepignore}' will be printed
        a list of lists:
            every line of inner list matching grep expression or starting with '{grepignore}' will be printed if there is at least one grep matching line WITHOUT '{grepignore}'
            Reason: prdh~Set-Cookie will print all Set-Cookie lines along with RRIDs, RRIDs without match are ignored
    """
    try:
        grepped = []
        for line in lines:
            if type(line) == str:
                # add lines if grepped or ignoring grep
                if grep in re.sub(r'\[[-1-9]*m', '', str(line)) or str(line).startswith('{grepignore}'):
                    grepped.append(line.lstrip('{grepignore}'))
            elif type(line) == list:
                # pick groups if at least one grepped
                sublines = [l for l in line if grep in re.sub(r'\[[-1-9]*m', '', str(l)) or str(l).startswith('{grepignore}')]
                if len([x for x in sublines if not str(x).startswith('{grepignore}')])>0:
                    grepped += [x.lstrip('{grepignore}') for x in sublines]
                
    except Exception as e:
        log.err('Cannot convert result into string:')
        log.err('See traceback:')
        traceback.print_exc()
        return

    log.tprint('\n'.join(grepped))

# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #

# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #

# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
"""
TEST COMMANDS
"""
def test_function(*args):
    #d = xmltodict.parse(weber.rrdb.rrs[1].response.data)
    #print(d)
    #d['html']['body']['center']['h1'] = 'Welcome to modified nginx!'
    #xml = xmltodict.unparse({'body': d['html']['body']})
    #print(xml)
    
    #print(weber.rrdb.rrs[1].response.find_tags('html'))
    for x in weber.rrdb.rrs[1].response.soup.prettify().splitlines()[100:200]:
        print(x)
    
    return []
add_command(Command('test', 'prints test message', '', test_function))
add_command(Command('testa', 'prints test equation', '', lambda *args: ['1+1=2']))

"""
EVENT COMMANDS
"""
add_command(Command('e', 'event functions', '', lambda *_: []))
# ea
def ea_function(*args):
    try:
        eid = int(args[1])
    except:
        log.err('Invalid event ID.')
        return
    if eid not in weber.events:
        weber.events[eid] = set()
    for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
        rr.eid = eid
        weber.events[eid].add(rrid)
    return []
add_command(Command('ea [<rrid>[:<rrid>]] eid', 'adds requests/responses into event', '', test_function))

# ep
def ep_function(*args): # TODO
    print(weber.events)
    return []
add_command(Command('ep [<eid>[:<eid>]]', 'print events (alias for \'pe\')', '', ep_function))


"""
PRINT COMMANDS
"""
add_command(Command('p', 'print', '', lambda *_: []))


def foreach_rrs(*args):
    result = []
    for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
        tmpresult = []
        tmpresult.append('{grepignore}%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE))

        try:
            cookies = rr.request.headers[b'Cookie'].split(b';')
            cookies = dict([tuple(c.split(b'=')) for c in cookies])
            maxlen = max([0]+[len(k.decode().strip()) for k in cookies.keys()])
        except:
            continue
        tmpresult += ['%*s: %s' % (maxlen, k.decode(), v.decode()) for k,v in cookies.items()]
        if len(tmpresult)>1:
            result.append(tmpresult)
    return result        
    

# pc
def pc_function(*args):
    result = []
    for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
        tmpresult = []
        tmpresult.append('{grepignore}%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE))
        try:
            cookies = rr.request.headers[b'Cookie'].split(b';')
            cookies = dict([tuple(c.split(b'=')) for c in cookies])
            maxlen = max([0]+[len(k.decode().strip()) for k in cookies.keys()])
        except:
            continue
        tmpresult += ['%*s: %s' % (maxlen, k.decode(), v.decode()) for k,v in cookies.items()]
        if len(tmpresult)>1:
            result.append(tmpresult)
    return result        
add_command(Command('pc [<rrid>[:<rrid>]]', 'print cookies', '', lambda: []))
add_command(Command('pcs [<rrid>[:<rrid>]]', 'print Set-Cookie occurences', '', lambda: []))
add_command(Command('pe [<eid>[:<eid>]]', 'print events', '', ep_function))

# pf
def find_tags_function(tags, valueonly, *args): 
    result = []
    for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
        tmpresult = []
        tmpresult.append('{grepignore}%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE))
        for tagname, attr_key, attr_value in tags:
            for t in rr.response.find_tags(tagname, attr_key=attr_key, attr_value=attr_value, form=('value' if valueonly else 'xml')):
                tmpresult.append(t)
        if len(tmpresult)>1:
            result.append(tmpresult)
    return result    
    #result = []
    #for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
    #    tmpresult = []
        
    #    tmpresult.append('{grepignore}%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE))
    #    for f in rr.response.find_tags(tagname, form=('value' if valueonly else 'xml')):
    #        tmpresult.append(f)
    #        tmpresult.append('')
    #    if len(tmpresult)>1:
    #        result += tmpresult
    #return result

def pf_function(*args):
    return find_tags_function([('form', None, None)], valueonly=False, *args)
add_command(Command('pf [<rrid>[:<rrid>]]', 'print forms', '', pf_function))

# pl
def pl_function(*args):
    return find_tags_function(Command.constants['link_tags'], valueonly=True, *args)
add_command(Command('pl [<rrid>[:<rrid>]]', 'print links', '', pl_function))
# plc
def plc_function(*args):
    return find_tags_function(Command.constants['link_tags'], valueonly=False, *args)
add_command(Command('plc [<rrid>[:<rrid>]]', 'print links with context', '', plc_function))
add_command(Command('pm', 'print URI mapping', '', lambda *args: ['%s <--> %s' % (k, v) for k, v in weber.mapping.l_r.items()]))

# pn
def pn_function(*args):
    return find_tags_function([('comment', None, None)], valueonly=True, *args)
    #return find_tags_function('comment', valueonly=True, *args)
    #return find_tags_function(lambda x: print('\n.', x, type(x.string), x.string), *args)
add_command(Command('pn [<rrid>[:<rrid>]]', 'print comments', '', pn_function))

# pp
def pp_function(*args):
    result = []
    for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
        tmpresult = []
        tmpresult.append('{grepignore}%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE))
        maxlen = max([0]+[len(k) for k in rr.request.parameters.keys()])
        tmpresult += ['%*s: %s' % (maxlen, k.decode(), v.decode()) for k, v in rr.request.parameters.items()]
        if len(tmpresult)>1:
            result.append(tmpresult)
    return result        
add_command(Command('pp [<rrid>[:<rrid>]]', 'print parameters', '', pp_function))

# pr
def pr_function(*args):
    #start, end = RRDB.get_interval(args, 1, len(weber.rrdb.rrs.items()))
    return weber.rrdb.overview(args)
add_command(Command('pr [<rrid>[:<rrid>]]', 'print request-response pairs', '', pr_function))

# prX
def prx_function(*args, mask=0xf): # print detailed headers/data/both of desired requests/responses/both
    showrequest = bool(mask & 0x8)
    showresponse = bool(mask & 0x4)
    showheaders = bool(mask & 0x2)
    showdata = bool(mask & 0x1)
    result = []

    for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
        tmpresult = ['{grepignore}%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE)]
        # deal with requests
        if showrequest:
            tmpresult += rr.request.lines(headers=showheaders, data=showdata)
        # deal with responses
        if showresponse:
            tmpresult += rr.response.lines(headers=showheaders, data=showdata)
        # add gathered to the final result
        if len([x for x in tmpresult if len(x.strip())>0])>1:
            result.append(tmpresult)
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
