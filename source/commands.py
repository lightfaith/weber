#!/usr/bin/env python3
"""
Commands and config methods are implemented here.
"""

import os, sys, re, traceback, tempfile, subprocess
from source import weber
from source import lib
from source import log
from source.lib import *
from source.structures import RRDB, Request, Response, Event, URI
import difflib

"""
Load configuration
"""
def reload_config():
    log.info('Loading config file...')
    with open(os.path.join(os.path.dirname(sys.argv[0]), 'weber.conf'), 'r') as f:
        for line in f.readlines():
            line = line.strip()
            if len(line) == 0 or line.startswith('#'):
                continue
            k, _, v = line.partition('=')
            log.debug_config('  line: \'%s\'' % (line))
            k = k.strip()
            v = v.strip()
            #if v.isdigit():
            #    v = int(v)
            #if lib.positive(v):
            #    v = True
            #if lib.negative(v):
            #    v = False
            if k in weber.config.keys():
                if weber.config[k][1] == bool:
                    v = positive(v)
                weber.config[k] = (weber.config[k][1](v), weber.config[k][1])
            else:
                weber.config[k] = (v, str)
            log.info('  %s = %s' % (k, v))
            log.debug_config('  parsed: %s = %s (%s)' % (k, v, str(type(v))))

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
        for k, v in sorted(weber.commands.items(), key=lambda x:x[0]):
            length = 40
            if k == '': # empty command - just print long description
                continue
            
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
        # show description
        for k, v in weber.commands.items():
            if k == command[:-1]:
                lines.append('')
                lines += ['    '+log.COLOR_DARK_GREEN+line+log.COLOR_NONE for line in v.description.splitlines()]
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
                if grep in re.sub(r'\[[1-9]*m', '', str(line)) or str(line).startswith('{grepignore}'):
                    grepped.append(line[12:] if line.startswith('{grepignore}') else line)
            elif type(line) == list:
                # pick groups if at least one grepped
                sublines = [l for l in line if grep in re.sub(r'\[[1-9]*m', '', str(l)) or str(l).startswith('{grepignore}')]
                if len([x for x in sublines if not str(x).startswith('{grepignore}') and len(x.strip())>0])>0:
                    grepped += [x[12:] if x.startswith('{grepignore}') else x for x in sublines]
                
    except Exception as e:
        log.err('Cannot convert result into string:')
        log.err('See traceback:')
        traceback.print_exc()
        return
    log.tprint('\n'.join(grepped))


"""
Important command functions
"""

def foreach_rrs(function, *args, fromtemplate=False, **kwargs):
    """
    This method iterates through desired RRs and runs desired function on them.
    RRs are expected to be the last item of *args.
    """
    result = []
    source = weber.tdb if fromtemplate else weber.rrdb
    try:
        desired_rrs, noproblem = source.get_desired_rrs(None if len(args)<1 else args[-1])
        desired_rrs = desired_rrs.items()
        arg_interval = -1 if noproblem else len(args)
    except ValueError: # no items yet
        return result
    except Exception as e:
        log.err('Cannot get desired rrs: %s' %  (str(e)))
        log.err('See traceback:')
        traceback.print_exc()
        desired_rrs = []
    for rrid, rr in desired_rrs:
        tmpresult = []
        tmpresult.append('{grepignore}%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE))
        kwargs['rr_count'] = len(desired_rrs)
        tmpresult += function(rrid, rr, *args[:arg_interval], **kwargs)
        #tmpresult += function(rrid, rr, *args[1:], **kwargs)
        tmpresult.append('')
        if len(tmpresult)>1:
            result.append(tmpresult)
        #print(result)
    return result

def find_tags(_, rr, *__, **kwargs):  # rrid, rr, *args, **kwargs
    #tags = kwargs['tags']
    startends = kwargs['startends']
    attrs = kwargs.get('attrs')
    valueonly = kwargs['valueonly']
    #for tagname, attr_key, attr_value in tags:
    #    for t in rr.response.find_tags(tagname, attr_key=attr_key, attr_value=attr_value, form=('value' if valueonly else 'xml')):
    #        tmpresult.append(t)
    #return tmpresult
    result = []
    r = rr.response_upstream if positive(weber.config['interaction.showupstream'][0]) else rr.response_downstream
    if r is None: # race condition, return nothing for now
        return result
    if attrs is None:
        for startbytes, endbytes in startends:
            result += [x[1].decode() for x in find_between(r.data, startbytes, endbytes, inner=valueonly)]
    else:
        for (startbytes, endbytes), attr in zip(startends, attrs):
            result += [x[1].decode() for x in r.find_html_attr(startbytes, endbytes, attr)]
    return result
    
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #

# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #

# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
help_description = """First, generate some traffic through the Weber proxy. After that, use `pr` command to get an overview.
"""
add_command(Command('', '', help_description, lambda: []))

"""
TEST COMMANDS
"""
def test_function(*_):
    #d = xmltodict.parse(weber.rrdb.rrs[1].response.data)
    #print(d)
    #d['html']['body']['center']['h1'] = 'Welcome to modified nginx!'
    #xml = xmltodict.unparse({'body': d['html']['body']})
    #print(xml)
    
    #print(weber.rrdb.rrs[1].response.find_tags('html'))
    #for x in weber.rrdb.rrs[1].response.soup.prettify().splitlines()[100:200]:
    #    print(x)
    print(weber.rrdb.rrs[1].response_upstream.find_tags('form'))
    return []
add_command(Command('test', 'prints test message', '', test_function))



"""
BRUTE COMMANDS
"""
# b
b_description = """
"""
def b_function(*args):
    return ['    %s  [%s, ...]' % (weber.brute[0], str(weber.brute[1][0]))]
    #return [str(x) for x in weber.brute]
add_command(Command('b', 'print brute values (alias for `pwb`)', b_description, b_function))

# bl
bl_description = """
"""
def bl_function(*args):
    try:
        path = args[0]
        with open(path, 'rb') as f:
            weber.brute = (path, [line.split(weber.config['brute.valueseparator'][0].encode()) for line in f.read().split(weber.config['brute.setseparator'][0].encode())])
        return []
    except Exception as e:
        log.err('Cannot open file.')
        return []
add_command(Command('bl <key> <path>', 'load file for brute', bl_description, bl_function))

# br
br_description = """
"""
# NOTE only one bruter at a time can be used
add_command(Command('br', 'brute from rrid', br_description, lambda *_: []))

# bra 
bra_description = """
"""
def bra_function(_, rr, *__, **___):
    # run with values
    if weber.brute is None: 
        log.err('No brute loaded, see `bl`.')
        return []
    max_setlen = max(len(x) for x in weber.brute[1])
    for brute_set in [x for x in weber.brute[1] if len(x) == max_setlen]:
        weber.proxy.add_connectionthread_from_template(rr, brute_set)
    return []
add_command(Command('bra [<rrid>[:<rrid>]]', 'brute from rrids for all sets', bra_description, lambda *args: foreach_rrs(bra_function, *args, fromtemplate=True)))
# TODO brd - brute rrid until difference

"""
COMPARE COMMANDS
"""
# c
c_description = """
"""
add_command(Command('c', 'compare', c_description, lambda *_: []))

# cr
cr_description = """
"""
add_command(Command('cr', 'compare requests/responses', cr_description, lambda *_: []))

crX_description = """
"""

#def crX_function(rrid1, rrid2, flag, function, **kwargs):
def crX_function(*args, **kwargs):
    # args: flag rrid1 rrid2
    #
    # flags: 1 - lines from first
    #        2 - lines from second
    #        c - common lines
    #        d - standard diff
    
    result = []
    # parse args
    try:
        flag = args[0]
        if flag not in '12cd':
            raise TypeError
    except:
        log.err('Invalid flag parameter.')
        return result
    try:
        rr1 = weber.rrdb.rrs[int(args[1])]
    except:
        log.err('Invaplid first RRID.')
        return result
    try:
        rr2 = weber.rrdb.rrs[int(args[2])]
    except:
        log.err('Invalid second RRID.')
        return result

    showrequest = bool(kwargs['mask'] & 0x8)
    showresponse = bool(kwargs['mask'] & 0x4)
    showheaders = bool(kwargs['mask'] & 0x2)
    showdata = bool(kwargs['mask'] & 0x1)
    
    # deal with requests for both rrs
    if showrequest:
        rrs_lines = []
        for rr in (rr1, rr2):
            r = rr.request_upstream if positive(weber.config['interaction.showupstream'][0]) else rr.request_downstream
            rrs_lines.append(r.lines(headers=showheaders, data=showdata))
        
        # diff
        diff_lines = [line for line in difflib.Differ().compare(rrs_lines[0], rrs_lines[1]) if not line.startswith('?')]
        if flag == '1':
            diff_lines = [line[2:] for line in diff_lines if line.startswith('-')]
        elif flag == '2':
            diff_lines = [line[2:] for line in diff_lines if line.startswith('+')]
        elif flag == 'c':
            diff_lines = [line[2:] for line in diff_lines if not line.startswith(('-', '+'))]
        result += diff_lines
        if showresponse:
            result.append('')

    # deal with responses for both rrs
    if showresponse:
        rrs_lines = []
        for rr in (rr1, rr2):
            r = rr.response_upstream if positive(weber.config['interaction.showupstream'][0]) else rr.response_downstream
            if r is None:
                rrs_lines.append(['Response not received yet...'])
            else:
                rrs_lines.append(r.lines(headers=showheaders, data=showdata))
        # diff
        diff_lines = [line for line in difflib.Differ().compare(rrs_lines[0], rrs_lines[1]) if not line.startswith('?')]
        if flag == '1':
            diff_lines = [line[2:] for line in diff_lines if line.startswith('-')]
        elif flag == '2':
            diff_lines = [line[2:] for line in diff_lines if line.startswith('+')]
        elif flag == 'c':
            diff_lines = [line[2:] for line in diff_lines if not line.startswith(('-', '+'))]
        result += diff_lines
    return result
    
add_command(Command('cra (12cd) rrid1 rrid2', 'diff two request-response pairs', crX_description, lambda *args: crX_function(*args, mask=0xf)))
add_command(Command('crh (12cd) rrid1 rrid2', 'diff two request-response headers', crX_description, lambda *args: crX_function(*args, mask=0xe)))
add_command(Command('crd (12cd) rrid1 rrid2', 'diff two request-response data', crX_description, lambda *args: crX_function(*args, mask=0xd)))
add_command(Command('crq (12cd) rrid1 rrid2', 'diff two requests', crX_description, lambda *args: crX_function(*args, mask=0xb)))
add_command(Command('crqh (12cd) rrid1 rrid2', 'diff two request headers', crX_description, lambda *args: crX_function(*args, mask=0xa)))
add_command(Command('crqd (12cd) rrid1 rrid2', 'diff two request data', crX_description, lambda *args: crX_function(*args, mask=0x9)))
add_command(Command('crs (12cd) rrid1 rrid2', 'diff two responses', crX_description, lambda *args: crX_function(*args, mask=0x7)))
add_command(Command('crsh (12cd) rrid1 rrid2', 'diff two response headers', crX_description, lambda *args: crX_function(*args, mask=0x6)))
add_command(Command('crsd (12cd) rrid1 rrid2', 'diff two response data', crX_description, lambda *args: crX_function(*args, mask=0x5)))

# cru diff upstream downstream
cru_description = """
"""
def cru_function(_, rr, *__, **___):
    reqd = rr.request_downstream.lines()
    requ = rr.request_upstream.lines()
    diffonly = lambda lines: [line for line in lines if line.startswith(('-', '+'))]
    result = diffonly(difflib.Differ().compare(reqd, requ))
    try:
        resd = rr.response_downstream.lines()
        resu = rr.response_upstream.lines()
        result += ['', ''] + diffonly(difflib.Differ().compare(resu, resd))
    except:
        pass
    return result
add_command(Command('cru rrid', 'diff upstream and downstream', cru_description, lambda *args: foreach_rrs(cru_function, *args)))










"""
EVENT COMMANDS
"""
# e
def e_function(*_): #TODO filter?
    result = []
    eid_len = max([3]+[len(str(e)) for e,_ in weber.events.values()])
    rr_len = max([5]+[len(','.join([str(r) for r in e.rrids])) for e in weber.events.values()])
    type_len = max([4]+[len(e.type) for e in weber.events.values()])
    log.tprint('    %-*s  %-*s  %s' % (eid_len, 'EID', rr_len, 'RRIDs', 'TYPE'))
    log.tprint('    %s  %s  %s' % ('='*eid_len, '='*rr_len, '='*type_len))
    for _, e in weber.events.items():
        result.append('    %*d  %-*s  %-s' % (eid_len, e.eid, rr_len, ','.join([str(r) for r in e.rrids]), e.type))
    return result
e_description = """Events are used to group relevant request-response pairs together. Use `e` to print them! 
"""
add_command(Command('e [<eid>[:<eid>]]', 'print events (alias for `pe`)', e_description, e_function))

# ea
def ea_function(*args):
    try:
        eid = int(args[0])
    except:
        log.err('Invalid event ID.')
        return []
    if len(args) != 2:
        log.err('Invalid arguments.')
        return []
    # delete active EID from desired RRs
    ed_function(*args[1:])
    # add new EID
    if eid not in weber.events.keys():
        weber.events[eid] = Event(eid)
    for rrid, rr in weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1])[0].items():
        rr.eid = eid
        weber.events[eid].rrids.add(rrid)
    return []
ea_description="""With `ea` command, request-response pairs are assigned an EID. Multiple request-respons pairs can be used at once. 
"""
add_command(Command('ea eid <rrid>[:<rrid>]', 'adds requests/responses into event', ea_description, ea_function))

def ed_function(*args):
    for rrid, rr in weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1])[0].items():
        for e in weber.events.values():
            if rrid in e.rrids:
                e.rrids.remove(rrid)
        rr.eid = None
    for empty in [ek for ek, ev in weber.events.items() if not ev.rrids]:
        del weber.events[empty]
    return []
ed_description="""With `ea` command, EID is removed from given request-response pairs.
"""
add_command(Command('ed <rrid>[:<rrid>]', 'delete requests/responses from event', ed_description, ed_function))

# et
def et_function(*args):
    try:
        eid = int(args[0])
        _ = weber.events[eid] # raises exception?
    except:
        log.err('Invalid eid.')
        return []
    try:
        t = ' '.join(args[1:])
    except: # No value - remove
        t = ''

    weber.events[eid].type = t
    return []
et_description = """Type can be assigned for events using `et` command. This can be useful for orientation among huge amount of traffic. Additionaly, security tests are performed on certain event types:
    login:
        Cookie management (#TODO)
    logout:
        Cookie management (#TODO)
    search:
        Reflected XSS (#TODO)
    email:
        automatic tests are ignored (#TODO)
""" # TODO what is tested for special types?
add_command(Command('et <eid> <type>', 'define type for an event', et_description, et_function))















"""
MODIFY COMMANDS
"""
m_description = """
"""
add_command(Command('m', 'modify', m_description, lambda *_: []))
mt_description = """
"""
add_command(Command('mt', 'modify template', mt_description, lambda *_: []))
mr_description="""Received requests and responses can be modified using your favourite text editor with `mrq` and `mrs`, respectively. Modifying multiple RRs is not supported (use spoofs instead). 
Favourite editor command can be configured under edit.command option.
"""
add_command(Command('mr', 'modify request/response', mr_description, lambda *_: []))
mrq_description="""
"""
mrs_description="""
"""
def mr_function(*args, fromtemplate=False):
    # parse command arguments
    try:
        tid = None
        rrid = int(args[1])
        #source = weber.tdb if fromtemplate else weber.rrdb

        if fromtemplate:
            # modify existing template
            source = weber.tdb.rrs[rrid]
        else:
            # work with real RRs
            source = weber.rrdb.rrs[rrid]
        if args[0] == 'request':
            r = source.request_upstream
        elif args[0] == 'response':
            r = source.response_upstream
        else:
            log.err('Invalid type.')
            return []

        if not r.tampering and not fromtemplate:
            # create template from RR
            log.info('Creating template from RR #%d...' % (rrid))
            tid = weber.tdb.add_rr(weber.rrdb.rrs[rrid].clone())
            source = weber.tdb.rrs[tid]
            if args[0] == 'request':
                r = source.request_upstream
            elif args[0] == 'response':
                r = source.response_upstream

        if r is None:
            log.err('Non-existent %s for RRID #%d.' % (args[0], rrid))
            return []
    except:
        log.err('Invalid RRID.')
        #traceback.print_exc()
        return []
    # suppress debugs and realtime overview
    oldconfig = {k:weber.config[k] for k in weber.config.keys() if k.startswith('debug.') or k == 'overview.realtime'}
    for k, _ in oldconfig.items():
        weber.config[k] = (False, weber.config[k][1])
    # write into temp file, open with desired editor
    with tempfile.NamedTemporaryFile() as f:
        f.write(r.bytes())
        f.flush()
        subprocess.call((weber.config['edit.command'][0] % (f.name)).split())
        f.seek(0)
        
        # read back
        changes = f.read()

    # write if changed
    if changes != r.bytes():
        if args[0] == 'request':
            source.request_upstream.parse(changes)
        elif args[0] == 'response':
            source.response_upstream.parse(changes)
    else:
        # delete template if just created
        if tid is not None:
            log.info('Template cancelled.')
            del weber.tdb.rrs[tid]
                
    # restore debug and realtime overview settings
    for k, v in oldconfig.items():
        weber.config[k] = v
    return []
        
add_command(Command('mrq <rrid>', 'modify request', mrq_description, lambda *args: mr_function('request', *args)))
add_command(Command('mrs <rrid>', 'modify response', mrs_description, lambda *args: mr_function('response', *args)))
add_command(Command('mtrq <rrid>', 'modify template request', mrq_description, lambda *args: mr_function('request', *args, fromtemplate=True)))
add_command(Command('mtrs <rrid>', 'modify template response', mrs_description, lambda *args: mr_function('response', *args, fromtemplate=True)))












"""
OPTIONS COMMANDS
"""
o_function = lambda *_: ['    %-20s  %s' % (k, str(v[0] if v[1] != str else '\''+v[0]+'\'').replace('\n', '\\n').replace('\r', '\\r')) for k,v in weber.config.items()]
o_description = """Active Weber configuration can be printed with `pwo` and `o` command.

Default configuration is located in source/weber.py.
User configuration can be specified in weber.conf in Weber root directory.
Configuration can be changed on the fly using the `os` command.
"""
add_command(Command('o', 'print Weber configuration (alias for `pwo`)', o_description, o_function))

# os
def os_function(*args):
    try:
        key = args[0]
        value = args[1]
    except:
        log.err('Invalid arguments.')
        return []
    typ = str if key not in weber.config.keys() else weber.config[key][1]
    if typ == bool:
        value = positive(value)
    weber.config[key] = (typ(value), typ)
    return []
os_description = """Active Weber configuration can be changed using the `os` command. User-specific keys can also be defined.
"""
add_command(Command('os <key> <value>', 'change Weber configuration', os_description, os_function))














"""
PRINT COMMANDS
"""
add_command(Command('p', 'print', '', lambda *_: []))

# pa
pa_description = """
"""
def pa_function(_, rr, *__, **___):
    result = []
    desired = 'upstream' if positive(weber.config['interaction.showupstream'][0]) else 'downstream'
    for source, severity, message in rr.analysis_notes:
        if source != desired:
            continue
        if severity == 'error':
            result += log.err(message, stdout=False)
        elif severity == 'warn':
            result += log.warn(message, stdout=False)
        elif severity == 'info':
            result += log.info(message, stdout=False)
        else:
            result.append(message)
    return result
add_command(Command('pa [<rrid>[:<rrid>]]', 'print analysis results', pa_description, lambda *args: foreach_rrs(pa_function, *args)))


# pc
def pc_function(_, rr, *__, **___):
    try:
        r = rr.request_upstream if positive(weber.config['interaction.showupstream'][0]) else rr.request_downstream
        cookies = r.headers[b'Cookie'].split(b';')
        cookies = dict([tuple(c.split(b'=')) for c in cookies])
        maxlen = max([0]+[len(k.decode().strip()) for k in cookies.keys()])
        return ['%*s: %s' % (maxlen, k.decode().strip(), v.decode()) for k,v in cookies.items()]
    except:
        return []
pc_description = """Cookies for specific requests are printed with `pc` command. To see Set-Cookie responses, use `pcs` command.
"""
add_command(Command('pc [<rrid>[:<rrid>]]', 'print cookies', pc_description, lambda *args: foreach_rrs(pc_function, *args)))
add_command(Command('ptc [<rrid>[:<rrid>]]', 'print cookies from templates', pc_description, lambda *args: foreach_rrs(pc_function, fromtemplate=True, *args)))

# pcs
def pcs_function(_, rr, *__, **___):
    try:
        r = rr.response_upstream if positive(weber.config['interaction.showupstream'][0]) else rr.response_downstream
        cookies = r.headers[b'Set-Cookie'].split(b';')
        attrs = dict([(tuple(c.split(b'=')+[b''])[:2]) for c in cookies])
        maxlen = max([0]+[len(k.decode().strip()) for k in attrs.keys()])
        return ['%*s%s' % (maxlen, k.decode().strip(), (': '+v.decode() if len(v)>0 else '')) for k,v in attrs.items()]
    except:
        #traceback.print_exc()
        return []
pcs_description = """Set-Cookie headers can be searched with `pcs` command.
"""
add_command(Command('pcs [<rrid>[:<rrid>]]', 'print Set-Cookie occurences', pcs_description, lambda *args: foreach_rrs(pcs_function, *args)))
add_command(Command('ptcs [<rrid>[:<rrid>]]', 'print Set-Cookie occurences from templates', pcs_description, lambda *args: foreach_rrs(pcs_function, fromtemplate=True, *args)))
add_command(Command('pe [<eid>[:<eid>]]', 'print events', e_description, e_function))

# ph
ph_description = """
"""
add_command(Command('ph', 'print HTML-related info', ph_description, lambda *_: []))
add_command(Command('pth', 'print HTML-related info in templates', ph_description, lambda *_: []))

# phc
phc_description = """HTML comments can be searched with `phc` command.
"""
add_command(Command('phc [<rrid>[:<rrid>]]', 'print comments', phc_description, lambda *args: foreach_rrs(find_tags, *args, startends=[(b'<!--', b'-->')], valueonly=False)))
add_command(Command('pthc [<rrid>[:<rrid>]]', 'print comments in templates', phc_description, lambda *args: foreach_rrs(find_tags, *args, fromtemplate=True, startends=[(b'<!--', b'-->')], valueonly=False)))

# phf
phf_description = """Forms present on given page are shown with `pf` command.
"""
add_command(Command('phf [<rrid>[:<rrid>]]', 'print HTML forms', phf_description, lambda *args: foreach_rrs(find_tags, *args, startends=[(b'<form', b'</form>')], valueonly=False)))
add_command(Command('pthf [<rrid>[:<rrid>]]', 'print HTML forms from templates', phf_description, lambda *args: foreach_rrs(find_tags, *args, fromtemplate=True, startends=[(b'<form', b'</form>')], valueonly=False)))

# phl
phl_description = """Links from all known tags are printed with `phl` command. To see their context, use `phlc` command.
"""
add_command(Command('phl [<rrid>[:<rrid>]]', 'print HTML links', phl_description, lambda *args: foreach_rrs(find_tags, *args, startends=[x[:2] for x in Response.link_tags], attrs=[x[2] for x in Response.link_tags], valueonly=True)))
add_command(Command('pthl [<rrid>[:<rrid>]]', 'print links from templates', phl_description, lambda *args: foreach_rrs(find_tags, *args, fromtemplate=True, startends=[x[:2] for x in Response.link_tags], attrs=[x[2] for x in Response.link_tags], valueonly=True)))
phlc_description = """Links from all known tags together with their context are printed with `phlc` command.
"""
add_command(Command('phlc [<rrid>[:<rrid>]]', 'print links with context', phlc_description, lambda *args: foreach_rrs(find_tags, *args, startends=[x[:2] for x in Response.link_tags], valueonly=False)))
add_command(Command('pthlc [<rrid>[:<rrid>]]', 'print links from templates with context', phlc_description, lambda *args: foreach_rrs(find_tags, *args, startends=[x[:2] for x in Response.link_tags], valueonly=False)))

# phm
phm_description = """HTML <main> tags can be searched with `phm` command.
"""
add_command(Command('phm [<rrid>[:<rrid>]]', 'print <main> elements', phm_description, lambda *args: foreach_rrs(find_tags, *args, startends=[(b'<main', b'</main>')], valueonly=False)))
add_command(Command('pthm [<rrid>[:<rrid>]]', 'print <main> elements in templates', phm_description, lambda *args: foreach_rrs(find_tags, *args, fromtemplate=True, startends=[(b'<main', b'</main>')], valueonly=False)))

# phs
phs_description = """
"""
add_command(Command('phs <start> <end>', 'search in HTML', phm_description, lambda *args: foreach_rrs(find_tags, *args, startends=[(args[0].encode(), args[1].encode())], valueonly=False)))
add_command(Command('pths <start> <end>', 'search in HTML of templates', phm_description, lambda *args: foreach_rrs(find_tags, *args, fromtemplate=True, startends=[(args[0].encode(), args[1].encode())], valueonly=False)))

# pp
def pp_function(_, rr, *__, **___):
    r = rr.request_upstream if positive(weber.config['interaction.showupstream'][0]) else rr.request_downstream
    maxlen = max([0]+[len(k) for k in r.parameters.keys()])
    return ['%*s: %s' % (maxlen, k.decode(), '' if v is None else v.decode()) for k, v in r.parameters.items()]
pp_description = """Parameters of selected requests are printed with `pp` command.
"""
add_command(Command('pp [<rrid>[:<rrid>]]', 'print parameters', pp_description, lambda *args: foreach_rrs(pp_function, *args)))
add_command(Command('ptp [<rrid>[:<rrid>]]', 'print template parameters', pp_description, lambda *args: foreach_rrs(pp_function, fromtemplate=True, *args)))

# pr_function defined in structures.py because it is also used by proxy (realtime overview)
pr_description = """Use `pr` command to get an overview of all captured request-response pairs. Size of the response and time can be optionally showed as well (using overview.size and overview.time configuration parameters) {#TODO}.
"""
add_command(Command('pr [<rrid>[:<rrid>]]', 'print request-response overview (alias for `pro`)', pr_description, lambda *args: weber.rrdb.overview(args, showlast=False, onlytampered=False)))
add_command(Command('pro [<rrid>[:<rrid>]]', 'print request-response pairs', pr_description, lambda *args: weber.rrdb.overview(args, showlast=False, onlytampered=False)))
add_command(Command('pt [<rrid>[:<rrid>]]', 'print templates overview (alias for `ptro`)', pr_description, lambda *args: weber.tdb.overview(args, showlast=False, onlytampered=False)))
add_command(Command('ptr [<rrid>[:<rrid>]]', 'print templates overview (alias for `ptro`)', pr_description, lambda *args: weber.tdb.overview(args, showlast=False, onlytampered=False)))
add_command(Command('ptro [<rrid>[:<rrid>]]', 'print templates overview', pr_description, lambda *args: weber.tdb.overview(args, showlast=False, onlytampered=False)))

# prol
prol_description="""
"""
add_command(Command('prol [<rrid>[:<rrid>]]', 'print last request-response overview', prol_description, lambda *args: weber.rrdb.overview(args, showlast=True, onlytampered=False)))
add_command(Command('ptrol [<rrid>[:<rrid>]]', 'print last template request-response overview', prol_description, lambda *args: weber.tdb.overview(args, showlast=True, onlytampered=False)))
# prot
prot_description="""
"""
add_command(Command('prot [<rrid>[:<rrid>]]', 'print request-response pairs in tamper state', prot_description, lambda *args: weber.rrdb.overview(args, showlast=False, onlytampered=True)))

# prX
def prx_function(_, rr, *__, **kwargs): # print detailed headers/data/both of desired requests/responses/both
    result = []
    showrequest = bool(kwargs['mask'] & 0x8)
    showresponse = bool(kwargs['mask'] & 0x4)
    showheaders = bool(kwargs['mask'] & 0x2)
    showdata = bool(kwargs['mask'] & 0x1)
    # deal with requests
    if showrequest:
        r = rr.request_upstream if positive(weber.config['interaction.showupstream'][0]) else rr.request_downstream
        result += r.lines(headers=showheaders, data=showdata)
        if showresponse:
            result.append('')
    # deal with responses
    if showresponse:
        r = rr.response_upstream if positive(weber.config['interaction.showupstream'][0]) else rr.response_downstream
        if r is None:
            result.append('Response not received yet...')
        else:
            result += r.lines(headers=showheaders, data=showdata)
    return result
prX_description="""Commands starting with `pr` are used to show request and/or response headers and/or data.
"""
add_command(Command('pra [<rrid>[:<rrid>]]', 'print requests-response pairs verbose', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0xf)))
add_command(Command('prh [<rrid>[:<rrid>]]', 'print request-response headers', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0xe)))
add_command(Command('prd [<rrid>[:<rrid>]]', 'print request-response data', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0xd)))
add_command(Command('prq [<rrid>[:<rrid>]]', 'print requests verbose', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0xb)))
add_command(Command('prqh [<rrid>[:<rrid>]]', 'print request headers', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0xa)))
add_command(Command('prqd [<rrid>[:<rrid>]]', 'print request data', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0x9)))
add_command(Command('prs [<rrid>[:<rrid>]]', 'print responses verbose', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0x7)))
add_command(Command('prsh [<rrid>[:<rrid>]]', 'print response headers', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0x6)))
add_command(Command('prsd [<rrid>[:<rrid>]]', 'print response data', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0x5)))

add_command(Command('ptra [<rrid>[:<rrid>]]', 'print template requests-response pairs verbose', prX_description, lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xf)))
add_command(Command('ptrh [<rrid>[:<rrid>]]', 'print template request-response headers', prX_description, lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xe)))
add_command(Command('ptrd [<rrid>[:<rrid>]]', 'print template request-response data', prX_description, lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xd)))
add_command(Command('ptrq [<rrid>[:<rrid>]]', 'print template requests', prX_description, lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xb)))
add_command(Command('ptrqh [<rrid>[:<rrid>]]', 'print template request headers', prX_description, lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xa)))
add_command(Command('ptrqd [<rrid>[:<rrid>]]', 'print template request data', prX_description, lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x9)))
add_command(Command('ptrs [<rrid>[:<rrid>]]', 'print template responses', prX_description, lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x7)))
add_command(Command('ptrsh [<rrid>[:<rrid>]]', 'print template response headers', prX_description, lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x6)))
add_command(Command('ptrsd [<rrid>[:<rrid>]]', 'print template response data', prX_description, lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x5)))


# pw 
add_command(Command('pw', 'print weber-related information', '', lambda *_: []))

# pwb
add_command(Command('pwb', 'print brute lists', b_description, b_function))

# pwm
def pwm_function(*args):
    k_len = max([len(str(k)) for k, _ in weber.mapping.l_r.items()])
    return ['    %*s <--> %s' % (k_len, k, v) for k, v in weber.mapping.l_r.items()]    
add_command(Command('pwm', 'print URI mapping', '', pwm_function))

# pwo
add_command(Command('pwo', 'print weber configuration', o_description, o_function))

# pws
pws_description="""Spoofing feature allows you to specify file which should be used instead the real response. Note that the request is sent to remote server to get valid HTML headers.
"""
def pws_function(*args):
    return ['%s -> %s' % (k, v) for k,v in weber.spoofs.items()]
add_command(Command('pws', 'print spoof settings', pws_description, pws_function))

# pwt
pwt_description="""Alive ConnectionThread objects are printed with `pt` command. This is mostly for debug purposes.
"""
add_command(Command('pwt', 'print alive threads', '', lambda *_: ['    %s' % ('?' if t.remoteuri is None else t.remoteuri) for t in weber.proxy.threads]))

"""
Quit
"""
add_command(Command('q', 'quit', '', lambda *_: [])) # solved in weber



"""
Spoofing
"""
# s
add_command(Command('s', 'print spoof settings (alias for `pws`)', pws_description, pws_function))

# sa
sa_description="""
"""
def sa_function(*args):
    try:
        uri = URI(args[0])
    except:
        log.err('Invalid URI.')
        return []
    try:
        with open(args[1], 'rb') as f:
            pass
    except:
        log.err('Cannot read file.')
        return []
    weber.spoofs[uri.get_value()] = args[1]
    return []
add_command(Command('sa <uri> <file>', 'add new spoof', sa_description, sa_function))
# sd
sd_description="""
"""
def sd_function(*args):
    try:
        del weber.spoofs[args[0]]
    except:
        log.err('Invalid spoof URI.')
    return []
add_command(Command('sd <uri>', 'delete spoof', sd_description, sd_function))





"""
TAMPER COMMANDS
"""
t_description = """
"""
add_command(Command('t', 'tamper', t_description, lambda *_: []))
tr_description = """
"""
add_command(Command('tr', 'tamper requests/responses', tr_description, lambda *_: []))

# trf
def trf_function(_, rr, *__, **___):
    # responses first so race condition won't occur
    try:
        rr.response_upstream.forward()
    except:
        pass
    try:
        rr.request_upstream.forward()
    except:
        pass
    return []
trf_description = """
"""
add_command(Command('trf [<rrid>[:<rrid>]]', 'forward tampered requests and responses', trf_description, lambda *args: foreach_rrs(trf_function, *args)))

# trq
trq_description="""
"""
def trq_function(*args):
    try:
        count = int(args[0])
    except:
        count = 1
    weber.proxy.tamper_request_counter = count
    log.info('Next %d requests will be tampered.' % (count))
    return []
add_command(Command('trq [<n>]', 'tamper next [n] request(s)', trq_description, trq_function))

# trqa
trqa_description = """Toggles tamper.requests value.
"""
def trqa_function(*_):
    trq = not(positive(weber.config['tamper.requests'][0]))
    weber.config['tamper.requests'] = (trq, weber.config['tamper.requests'][1])
    weber.proxy.tamper_request_counter = 0
    log.info('Requests will be %s by default.' % ('TAMPERED' if trq else 'FORWARDED'))
    return []
add_command(Command('trqa', 'toggle default request tamper behavior', trqa_description, trqa_function))

# trs
trs_description="""
"""
def trs_function(*args):
    try:
        count = int(args[0])
    except:
        count = 1
    weber.proxy.tamper_response_counter = count
    log.info('Next %d responses will be tampered.' % (count))
    return []
add_command(Command('trs [<n>]', 'tamper next [n] response(s)', trs_description, trs_function))

# trsa
trsa_description = """Toggles tamper.responses value.
"""
def trsa_function(*_):
    trs = not(positive(weber.config['tamper.responses'][0]))
    weber.config['tamper.responses'] = (trs, weber.config['tamper.responses'][1])
    weber.proxy.tamper_response_counter = 0
    log.info('Responses will be %s by default.' % ('TAMPERED' if trs else 'FORWARDED'))
    return []
add_command(Command('trsa', 'toggle default response tamper behavior', trsa_description, trsa_function))

# trqf
def trqf_function(_, rr, *__, **___):
    try:
        rr.request_upstream.forward()
    except:
        log.err('No request is available.')
    return []
trqf_description = """
"""
add_command(Command('trqf [<rrid>[:<rrid>]]', 'forward tampered request', trqf_description, lambda *args: foreach_rrs(trqf_function, *args)))

# trsf
def trsf_function(_, rr, *__, **___):
    try:
        rr.response_upstream.forward()
    except: # no response
        log.info('No response is available.')
    return []
trsf_description = """
"""
add_command(Command('trsf [<rrid>[:<rrid>]]', 'forward tampered response', trsf_description, lambda *args: foreach_rrs(trsf_function, *args)))





"""
WRITE COMMANDS
"""
# w
w_description = """
"""
add_command(Command('w', 'write', w_description, lambda *_: []))
# wr
wr_description = """
"""
add_command(Command('wr', 'write requests/responses into file', wr_description, lambda *_: []))

# wrX
def wrx_function(rrid, rr, *args, **kwargs): # write headers/data/both of desired requests/responses/both into file
    data = []
    try:
        if kwargs.get('rr_count') == 1:
            path = args[0]
        else:
            path = '%s_%d' % (args[0], rrid)
    except:
        log.err('Path to file not specified or incorrect RR interval.')
        return []
    showrequest = bool(kwargs['mask'] & 0x8)
    showresponse = bool(kwargs['mask'] & 0x4)
    showheaders = bool(kwargs['mask'] & 0x2)
    showdata = bool(kwargs['mask'] & 0x1)
    # deal with requests
    if showrequest:
        r = rr.request_upstream if positive(weber.config['interaction.showupstream'][0]) else rr.request_downstream
        data += r.lines(headers=showheaders, data=showdata, as_string=False)
        if showresponse:
            data.append(b'')
    # deal with responses
    if showresponse:
        r = rr.response_upstream if positive(weber.config['interaction.showupstream'][0]) else rr.response_downstream
        if r is None:
            data.append(b'Response not received yet...')
        else:
            data += r.lines(headers=showheaders, data=showdata, as_string=False)
    try:
        with open(path, 'wb') as f:
            f.write(b'\n'.join(data))
    except Exception as e:
        log.err('Cannot write into file \'%s\'.' % (str(path)))
        print(e)
    return []

wrX_description="""
"""
add_command(Command('wra <file> [<rrid>[:<rrid>]]', 'write requests and responses', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, mask=0xf)))
add_command(Command('wrh <file> [<rrid>[:<rrid>]]', 'write request and response headers', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, mask=0xe)))
add_command(Command('wrd <file> [<rrid>[:<rrid>]]', 'write request and response data', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, mask=0xd)))
add_command(Command('wrq <file> [<rrid>[:<rrid>]]', 'write requests verbose', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, mask=0xb)))
add_command(Command('wrqh <file> [<rrid>[:<rrid>]]', 'write request headers', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, mask=0xa)))
add_command(Command('wrqd <file> [<rrid>[:<rrid>]]', 'write request data', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, mask=0x9)))
add_command(Command('wrs <file> [<rrid>[:<rrid>]]', 'write responses verbose', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, mask=0x7)))
add_command(Command('wrsh <file> [<rrid>[:<rrid>]]', 'write response headers', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, mask=0x6)))
add_command(Command('wrsd <file> [<rrid>[:<rrid>]]', 'write response data', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, mask=0x5)))

add_command(Command('wtra <file> [<rrid>[:<rrid>]]', 'write template requests and responses', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0xf)))
add_command(Command('wtrh <file> [<rrid>[:<rrid>]]', 'write template request and response headers', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0xe)))
add_command(Command('wtrd <file> [<rrid>[:<rrid>]]', 'write template request and response data', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0xd)))
add_command(Command('wtrq <file> [<rrid>[:<rrid>]]', 'write template requests verbose', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0xb)))
add_command(Command('wtrqh <file> [<rrid>[:<rrid>]]', 'write template request headers', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0xa)))
add_command(Command('wtrqd <file> [<rrid>[:<rrid>]]', 'write template request data', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0x9)))
add_command(Command('wtrs <file> [<rrid>[:<rrid>]]', 'write template responses verbose', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0x7)))
add_command(Command('wtrsh <file> [<rrid>[:<rrid>]]', 'write template response headers', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0x6)))
add_command(Command('wtrsd <file> [<rrid>[:<rrid>]]', 'write template response data', wrX_description, lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0x5)))



