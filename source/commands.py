#!/usr/bin/env python3
"""
Commands and config methods are implemented here.
"""

import os, sys, re, traceback, tempfile, subprocess
from source import weber
from source import lib
from source import log
from source.docs import doc
#from source.protocols import protocols
from source.protocols.protocols import *
from source.lib import *
from source.structures import RRDB, Event, URI
import difflib
from source.fd_debug import *


"""
Universal class for commands.
"""
class Command():

    def __init__(self, command, apropos, doc_tag, function):
        self.command = command
        self.apropos = apropos
        self.doc_tag = doc_tag
        self.description = doc.get(doc_tag) or ''
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
    modifier = weber.config['interaction.command_modifier'][0]
    log.debug_command('  Fullcmd: \'%s\'' % (fullcommand))
    parts = list(filter(None, re.split('(~~|~|\%s)' % (modifier), fullcommand)))
    command = parts[0]
    phase = {'~': False, '~~': False, modifier: False}
    
    # test if it is documented
    try:
        if not weber.commands[command.rstrip('?')].description.strip():
            log.warn('The command has no documentation.')
    except:
        # command does not exist, but it will be dealt in a while
        pass 
    # help or command?
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
        # show description if '??'
        if command.endswith('??'):
            for k, v in weber.commands.items():
                if k == command[:-2]:
                    lines.append('')
                    lines += ['    '+log.COLOR_DARK_GREEN+line+log.COLOR_NONE for line in v.description.splitlines()]
    else:
        try:
            command, *args = command.split(' ')
            log.debug_command('  Command: \'%s\'' % (command))
            log.debug_command('  Args:    %s' % (str(args)))
            # run command
            lines = weber.commands[command].run(*args)

        except Exception as e:
            log.err('Cannot execute command \''+command+'\': '+str(e)+'.')
            log.err('See traceback:')
            traceback.print_exc()
            return

    # Lines can be:
    #     a list of strings:
    #         every line matching grep expression or starting with '{grepignore}' will be printed
    #     a list of lists:
    #         every line of inner list matching grep expression or starting with '{grepignore}' will be printed if there is at least one grep matching line WITHOUT '{grepignore}'
    #         Reason: prsh~Set-Cookie will print all Set-Cookie lines along with RRIDs, RRIDs without match are ignored
    result_lines = []
    nocolor = lambda line: re.sub('\033\\[[0-9]+m', '', str(line))
    
    # go through all command parts and modify those lines
    for part in parts[1:]:
        tmp_lines = []
        # special character? set phase
        if part in phase.keys():
            # another phase active? bad command...
            if any(phase.values()):
                log.err('Invalid command.')
                return
            # no phase? set it
            phase[part] = True
            continue
        # no phase and no special character? bad command...
        elif not any(phase.values()):
            log.err('Invalid command (bad regex)!')
            return
        

        # deal with phases
        elif phase['~']:
            # normal grep
            log.debug_command('  grep \'%s\'' % part)
            phase['~'] = False
            for line in lines:
                if type(line) == str:
                    if str(line).startswith('{grepignore}') or part in nocolor(line):
                        tmp_lines.append(line)
                elif type(line) == list:
                    # pick groups if at least one line starts with {grepignore} or matches grep
                    sublines = [l for l in line if str(l).startswith('{grepignore}') or part in nocolor(l)]
                    if [x for x in sublines if not str(x).startswith('{grepignore}') and x.strip()]:
                        tmp_lines.append(sublines)
        elif phase['~~']:
            # regex grep
            log.debug_command('  regex_grep \'%s\'' % part)
            phase['~~'] = False
            for line in lines:
                if type(line) == str:
                    if str(line).startswith('{grepignore}') or re.search(part, nocolor(line.strip())):
                        tmp_lines.append(line)
                elif type(line) == list:
                    # pick groups if at least one line starts with {grepignore} or matches grep
                    sublines = [l for l in line if str(l).startswith('{grepignore}') or re.search(part, nocolor(l.strip()))]
                    if [x for x in sublines if not str(x).startswith('{grepignore}') and x.strip()]:
                        tmp_lines.append(sublines)
        elif phase[modifier]: # TODO line intervals and more features
            # modifying
            log.debug_command('  modification \'%s\'' % part)
            phase[modifier] = False
            # less? 
            if part.endswith('L'):
                less_lines = []
                for line in lines:
                    if type(line) == str:
                        less_lines.append(nocolor(re.sub('^\\{grepignore\\}', '', line)))
                    elif type(line) == list:
                        for subline in line:
                            less_lines.append(nocolor(re.sub('^\\{grepignore\\}', '', subline)))
                with tempfile.NamedTemporaryFile() as f:
                    f.write('\n'.join(less_lines).encode())
                    f.flush()
                    subprocess.call(['less', f.name])
                return

        # use parsed lines for more parsing
        lines = tmp_lines

    # any phase remained? that's wrong
    if any(phase.values()):
        log.err('Invalid command.')
        return
    
    for line in lines:
        if type(line) == str:
            log.tprint(re.sub('^\\{grepignore\\}', '', line))
        elif type(line) == bytes:
            log.tprint(re.sub('^\\{grepignore\\}', '', line.decode()))
        elif type(line) == list:
            for subline in line:
                log.tprint(re.sub('^\\{grepignore\\}', '', subline))




"""
Important command functions
"""

def foreach_rrs(function, *args, fromtemplate=False, **kwargs):
    """
    This method iterates through desired RRs and runs desired function on them.
    RRs are expected to be the last item of *args.
    """
    args = list(filter(None, args))
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
        if len(list(filter(None, tmpresult)))>1:
            result.append(tmpresult)
        #print(result)
    return result

def find_tags(_, rr, *__, **kwargs):  # rrid, rr, *args, **kwargs
    startends = kwargs['startends']
    attrs = kwargs.get('attrs')
    valueonly = kwargs['valueonly']
    
    r = rr.response_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.response_downstream
    if r is None: # race condition, return nothing for now
        return []
    return r.find_tags(startends, attrs, valueonly)
    
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #

# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #

# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
add_command(Command('', '', 'help', lambda: []))
add_command(Command('help', '', 'help', lambda *_: [line for line in doc['help'].format(remote=list(weber.mapping.l_r.items())[0][1].domain, local=weber.config['proxy.host'][0], port=weber.config['proxy.port'][0], sslport=weber.config['proxy.sslport'][0], modifier=weber.config['interaction.command_modifier'][0]).splitlines()]))

"""
TEST COMMANDS
"""
def test_function(*_):
    result = []
    for server in weber.servers:
        result.append(str(server.uri))
        result.append(str(server.rrs))
        result.append('')
    return result
add_command(Command('test', 'prints test message', '', test_function))

def prompt_function(*_): # TODO for testing only!
    while True:
        print('> ', end='')
        exec(input())
    return []
add_command(Command('prompt', 'gives python3 shell', '', prompt_function))


"""
ANALYSIS COMMANDS
"""
# ap
def ap_function(*args):
    result = []
    for k, v in weber.analysis.items():
        result.append('    %s %s' % ('+' if v['enabled'] else '-', k))
        # rr_tests
        if 'rr_tests' in v.keys():
            result.append('       RR tests:')
            for testname, info, *_ in v['rr_tests']:
                result.append('        %s: %s' % (testname, info[1]))
    return result

add_command(Command('ap', 'print analysis packs (alias for `pap`)', 'ap', ap_function))
add_command(Command('pap', 'print analysis packs', 'ap', ap_function))

# ape, apd
def ap_function(*args, enable):
    try:
        weber.analysis[args[0]]['enabled'] = enable
    except:
        log.err('Invalid analysis pack name.')
    return []

add_command(Command('ape <pack>', 'enable analysis pack', 'ap', lambda *args: ap_function(*args, enable=True)))
add_command(Command('apd <pack>', 'disable analysis pack', 'ap', lambda *args: ap_function(*args, enable=False)))

# ar
def ar_function(_, rr, *__, **___):
    result = []
    rr.analyze()
    if rr.analysis_notes:
       result += par_function(_, rr, *__, **___)
    return result
add_command(Command('ar [<rrid>[:<rrid>]]', 'run RR analysis on specified request-response pairs', 'ar', lambda *args: foreach_rrs(ar_function, *args)))


"""
BRUTE COMMANDS
"""
# b
def b_function(*args):
    if weber.brute:
        return ['    %s  [%s, ...]' % (weber.brute[0], str(weber.brute[1][0]))]
    else:
        log.err('No brute loaded, see `bl`.')
        return []
add_command(Command('b', 'brute-force (alias for `pwb`)', 'b', b_function))

# bl
def bl_function(*args):
    try:
        path = args[0]
        with open(path, 'rb') as f:
            weber.brute = (path, [line.split(weber.config['brute.value_separator'][0].encode()) for line in f.read().split(weber.config['brute.set_separator'][0].encode())])
        return []
    except Exception as e:
        log.err('Cannot open file (%s).' % (str(e)))
        return []
add_command(Command('bl <path>', 'load file for brute', 'bl', bl_function))

# bfi
def bfi_function(_, rr, *__, **___):
    data = rr.__bytes__()

    return [] # TODO change
add_command(Command('bfi [<rrid>[:<rrid>]]', 'brute fault injection from template rrids', 'bfi', lambda *args: foreach_rrs(bfi_function, *args, fromtemplate=True)))

# br
# NOTE only one bruter at a time can be used
add_command(Command('br', 'brute from template rrid', 'br', lambda *_: []))

# bra 
def bra_modifier(data, brute_set):
    placeholder = weber.config['brute.placeholder'][0].encode()
    for i in range(len(brute_set)):
        data = data.replace(b'%s%d%s' % (placeholder, i, placeholder), brute_set[i])
    return data
    
def bra_function(_, rr, *__, **___):
    # run with values
    if weber.brute is None: 
        log.err('No brute loaded, see `bl`.')
        return []
    max_setlen = max(len(x) for x in weber.brute[1])
    for brute_set in [x for x in weber.brute[1] if len(x) == max_setlen]:
        weber.proxy.add_connectionthread_from_template(rr, lambda data: bra_modifier(data, brute_set))
    return []
add_command(Command('bra [<rrid>[:<rrid>]]', 'brute from template rrids for all sets', 'bra', lambda *args: foreach_rrs(bra_function, *args, fromtemplate=True)))
# TODO brd - brute rrid until difference

def brf_function(_, rr, *__, **___):
    weber.proxy.add_connectionthread_from_template(rr, lambda data: data)
    return []
add_command(Command('brf [<rrid>[:<rrid>]]', 'forward template rrid without modification', 'brf', lambda *args: foreach_rrs(brf_function, *args, fromtemplate=True)))

"""
COMPARE COMMANDS
"""
# c
add_command(Command('c', 'compare', 'c', lambda *_: []))

# cr
add_command(Command('cr', 'compare requests/responses', 'cr', lambda *_: []))

#def crX_function(rrid1, rrid2, flag, function, **kwargs):
def crX_function(*args, **kwargs):
    # args: flag rrid1 rrid2
    #
    # flags: 1 - lines only present in first
    #        2 - lines only present in second
    #        c - common lines
    #        d - different lines only
    #        D - standard diff
    
    result = []
    # parse args
    try:
        flag = args[0]
        if flag not in '12cdD':
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
            r = rr.request_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.request_downstream
            rrs_lines.append(r.lines(headers=showheaders, data=showdata))
        
        # diff
        diff_lines = [line for line in difflib.Differ().compare(rrs_lines[0], rrs_lines[1]) if not line.startswith('?')]
        if flag == '1':
            diff_lines = [line[2:] for line in diff_lines if line.startswith('-')]
        elif flag == '2':
            diff_lines = [line[2:] for line in diff_lines if line.startswith('+')]
        elif flag == 'c':
            diff_lines = [line[2:] for line in diff_lines if not line.startswith(('-', '+'))]
        elif flag == 'd':
            diff_lines = [line for line in diff_lines if line.startswith(('-', '+'))]
        result += diff_lines
        if showresponse:
            result.append('')

    # deal with responses for both rrs
    if showresponse:
        rrs_lines = []
        for rr in (rr1, rr2):
            r = rr.response_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.response_downstream
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
        elif flag == 'd':
            diff_lines = [line for line in diff_lines if line.startswith(('-', '+'))]
        result += diff_lines
    return result
    
add_command(Command('cra (12cdD) rrid1 rrid2', 'diff two request-response pairs', 'crX', lambda *args: crX_function(*args, mask=0xf)))
add_command(Command('crh (12cdD) rrid1 rrid2', 'diff two request-response headers', 'crX', lambda *args: crX_function(*args, mask=0xe)))
add_command(Command('crd (12cdD) rrid1 rrid2', 'diff two request-response data', 'crX', lambda *args: crX_function(*args, mask=0xd)))
add_command(Command('crq (12cdD) rrid1 rrid2', 'diff two requests', 'crX', lambda *args: crX_function(*args, mask=0xb)))
add_command(Command('crqh (12cdD) rrid1 rrid2', 'diff two request headers', 'crX', lambda *args: crX_function(*args, mask=0xa)))
add_command(Command('crqd (12cdD) rrid1 rrid2', 'diff two request data', 'crX', lambda *args: crX_function(*args, mask=0x9)))
add_command(Command('crs (12cdD) rrid1 rrid2', 'diff two responses', 'crX', lambda *args: crX_function(*args, mask=0x7)))
add_command(Command('crsh (12cdD) rrid1 rrid2', 'diff two response headers', 'crX', lambda *args: crX_function(*args, mask=0x6)))
add_command(Command('crsd (12cdD) rrid1 rrid2', 'diff two response data', 'crX', lambda *args: crX_function(*args, mask=0x5)))

# cru diff upstream downstream
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
add_command(Command('cru rrid', 'diff upstream and downstream', 'cru', lambda *args: foreach_rrs(cru_function, *args)))










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
add_command(Command('e [<eid>[:<eid>]]', 'events (alias for `pe`)', 'e', e_function))

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
add_command(Command('ea eid <rrid>[:<rrid>]', 'adds requests/responses into event', 'ea', ea_function))

def ed_function(*args):
    for rrid, rr in weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1])[0].items():
        for e in weber.events.values():
            if rrid in e.rrids:
                e.rrids.remove(rrid)
        rr.eid = None
    for empty in [ek for ek, ev in weber.events.items() if not ev.rrids]:
        del weber.events[empty]
    return []
add_command(Command('ed <rrid>[:<rrid>]', 'delete requests/responses from event', 'ed', ed_function))

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
add_command(Command('et <eid> <type>', 'define type for an event', 'et', et_function))















"""
MODIFY COMMANDS
"""
add_command(Command('m', 'modify', 'm', lambda *_: []))
add_command(Command('mt', 'modify template', 'mt', lambda *_: []))
add_command(Command('mr', 'modify request/response', 'mr', lambda *_: []))
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
        
add_command(Command('mrq <rrid>', 'modify request', 'mrq', lambda *args: mr_function('request', *args)))
add_command(Command('mrs <rrid>', 'modify response', 'mrs', lambda *args: mr_function('response', *args)))
add_command(Command('mtrq <rrid>', 'modify template request', 'mrq', lambda *args: mr_function('request', *args, fromtemplate=True)))
add_command(Command('mtrs <rrid>', 'modify template response', 'mrs', lambda *args: mr_function('response', *args, fromtemplate=True)))












"""
OPTIONS COMMANDS
"""
o_function = lambda *_: ['    %-30s  %s' % (k, str(v[0] if v[1] != str else '\''+v[0]+'\'').replace('\n', '\\n').replace('\r', '\\r')) for k,v in weber.config.items()]
add_command(Command('o', 'Weber options (alias for `pwo`)', 'o', o_function))

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
add_command(Command('os <key> <value>', 'change Weber configuration', 'os', os_function))














"""
PRINT COMMANDS
"""
add_command(Command('p', 'print', '', lambda *_: []))

# par
def par_function(_, rr, *__, **___):
    result = []
    desired = 'upstream' if positive(weber.config['interaction.show_upstream'][0]) else 'downstream'
    for source, testname, severity, message, certainity in rr.analysis_notes:
        if source != desired:
            continue
        color = log.COLOR_NONE
        if severity == 'SECURITY':
            color = log.COLOR_RED
        if severity == 'WARNING':
            color = log.COLOR_YELLOW
        if severity == 'INFOLEAK':
            color = log.COLOR_CYAN

        if certainity:
            color += log.COLOR_BOLD
        result += log.info('%s<%s>%s %s: %s' % (color, severity, log.COLOR_NONE, testname, message), stdout=False)
    return result
add_command(Command('par [<rrid>[:<rrid>]]', 'print results of RR analysis', 'par', lambda *args: foreach_rrs(par_function, *args)))


# pc
def pc_function(_, rr, *__, **___):
    try:
        r = rr.request_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.request_downstream
        cookies = r.headers[b'Cookie'].split(b';')
        cookies = dict([tuple(c.split(b'=')) for c in cookies])
        maxlen = max([0]+[len(k.decode().strip()) for k in cookies.keys()])
        return ['%*s: %s' % (maxlen, k.decode().strip(), v.decode()) for k,v in cookies.items()]
    except:
        return []
add_command(Command('pc [<rrid>[:<rrid>]]', 'print cookies', 'pc', lambda *args: foreach_rrs(pc_function, *args)))
add_command(Command('ptc [<rrid>[:<rrid>]]', 'print cookies from templates', 'pc', lambda *args: foreach_rrs(pc_function, fromtemplate=True, *args)))

# pcs
def pcs_function(_, rr, *__, **___):
    try:
        r = rr.response_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.response_downstream
        cookies = r.headers[b'Set-Cookie'].split(b';')
        attrs = dict([(tuple(c.strip().split(b'=')+[b''])[:2]) for c in cookies])
        maxlen = max([0]+[len(k.decode()) for k in attrs.keys()])
        return ['%*s%s' % (maxlen, k.decode(), (': '+v.decode() if len(v)>0 else '')) for k,v in attrs.items()]
    except:
        #traceback.print_exc()
        return []
add_command(Command('pcs [<rrid>[:<rrid>]]', 'print Set-Cookie occurences', 'pcs', lambda *args: foreach_rrs(pcs_function, *args)))
add_command(Command('ptcs [<rrid>[:<rrid>]]', 'print Set-Cookie occurences from templates', 'pcs', lambda *args: foreach_rrs(pcs_function, fromtemplate=True, *args)))
add_command(Command('pe [<eid>[:<eid>]]', 'print events', 'e', e_function))


# ph - only relevant for HTTP
if 'source.protocols.http' in sys.modules.keys():
    add_command(Command('ph', 'print HTML-related info', 'ph', lambda *_: []))
    add_command(Command('pth', 'print HTML-related info in templates', 'ph', lambda *_: []))

    # phc
    add_command(Command('phc [<rrid>[:<rrid>]]', 'print comments', 'phc', lambda *args: foreach_rrs(find_tags, *args, startends=[(b'<!--', b'-->')], valueonly=False)))
    add_command(Command('pthc [<rrid>[:<rrid>]]', 'print comments in templates', 'phc', lambda *args: foreach_rrs(find_tags, *args, fromtemplate=True, startends=[(b'<!--', b'-->')], valueonly=False)))

    # phf
    add_command(Command('phf [<rrid>[:<rrid>]]', 'print HTML forms', 'phf', lambda *args: foreach_rrs(find_tags, *args, startends=[(b'<form', b'</form>')], valueonly=False)))
    add_command(Command('pthf [<rrid>[:<rrid>]]', 'print HTML forms from templates', 'phf', lambda *args: foreach_rrs(find_tags, *args, fromtemplate=True, startends=[(b'<form', b'</form>')], valueonly=False)))

    # phl
    add_command(Command('phl [<rrid>[:<rrid>]]', 'print HTML links', 'phl', lambda *args: foreach_rrs(find_tags, *args, startends=[x[:2] for x in sys.modules['source.protocols.http'].HTTP.link_tags], attrs=[x[2] for x in sys.modules['source.protocols.http'].HTTP.link_tags], valueonly=True)))
    add_command(Command('pthl [<rrid>[:<rrid>]]', 'print links from templates', 'phl', lambda *args: foreach_rrs(find_tags, *args, fromtemplate=True, startends=[x[:2] for x in sys.modules['source.protocols.http'].HTTP.link_tags], attrs=[x[2] for x in sys.modules['source.protocols.http'].HTTP.link_tags], valueonly=True)))
    
    add_command(Command('phlc [<rrid>[:<rrid>]]', 'print links with context', 'phlc', lambda *args: foreach_rrs(find_tags, *args, startends=[x[:2] for x in sys.modules['source.protocols.http'].HTTP.link_tags], valueonly=False)))
    add_command(Command('pthlc [<rrid>[:<rrid>]]', 'print links from templates with context', 'phlc', lambda *args: foreach_rrs(find_tags, *args, startends=[x[:2] for x in sys.modules['source.protocols.http'].HTTP.link_tags], valueonly=False)))

    # phm
    add_command(Command('phm [<rrid>[:<rrid>]]', 'print <main> elements', 'phm', lambda *args: foreach_rrs(find_tags, *args, startends=[(b'<main', b'</main>')], valueonly=False)))
    add_command(Command('pthm [<rrid>[:<rrid>]]', 'print <main> elements in templates', 'phm', lambda *args: foreach_rrs(find_tags, *args, fromtemplate=True, startends=[(b'<main', b'</main>')], valueonly=False)))

    # phs
    add_command(Command('phs <start> <end>', 'search in HTML', 'phm', lambda *args: foreach_rrs(find_tags, *args, startends=[(args[0].encode(), args[1].encode())], valueonly=False)))
    add_command(Command('pths <start> <end>', 'search in HTML of templates', 'phm', lambda *args: foreach_rrs(find_tags, *args, fromtemplate=True, startends=[(args[0].encode(), args[1].encode())], valueonly=False)))


# pp
def pp_function(_, rr, *__, **___):
    r = rr.request_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.request_downstream
    maxlen = max([0]+[len(k) for k in r.parameters.keys()])
    return ['%*s: %s' % (maxlen, k.decode(), '' if v is None else v.decode()) for k, v in r.parameters.items()]
add_command(Command('pp [<rrid>[:<rrid>]]', 'print parameters', 'pp', lambda *args: foreach_rrs(pp_function, *args)))
add_command(Command('ptp [<rrid>[:<rrid>]]', 'print template parameters', 'pp', lambda *args: foreach_rrs(pp_function, fromtemplate=True, *args)))

# pr_function defined in structures.py because it is also used by proxy (realtime overview)
def overview_handler(args, source, show_last=False, only_tampered=False, only_with_analysis=False):
    #args = list(filter(None, args))
    show_event = False
    show_size = False
    show_time = False
    show_uri = False
    if args and re.match('^[estu]+$', args[0]): # some modifiers (defaults are considered in overview() function)
        show_event = 'e' in args[0]
        show_size = 's' in args[0]
        show_time = 't' in args[0]
        show_uri = 'u' in args[0]
        args = args[1:]
    return source.overview(args, show_event=show_event, show_size=show_size, show_time=show_time, show_uri=show_uri, show_last=show_last, only_tampered=only_tampered, only_with_analysis=only_with_analysis)

add_command(Command('pr [estu] [<rrid>[:<rrid>]]', 'print request-response overview (alias for `pro`)', 'pr', lambda *args: overview_handler(args, source=weber.rrdb)))

add_command(Command('pro [estu] [<rrid>[:<rrid>]]', 'print request-response pairs', 'pr', lambda *args: overview_handler(args, source=weber.rrdb)))
add_command(Command('pt [estu] [<rrid>[:<rrid>]]', 'print templates overview (alias for `ptro`)', 'pr', lambda *args: overview_handler(args, source=weber.tdb)))
add_command(Command('ptr [estu] [<rrid>[:<rrid>]]', 'print templates overview (alias for `ptro`)', 'pr', lambda *args: overview_handler(args, source=weber.tdb)))
add_command(Command('ptro [estu] [<rrid>[:<rrid>]]', 'print templates overview', 'pr', lambda *args: overview_handler(args, source=weber.tdb)))

# prol
add_command(Command('prol [estu] [<rrid>[:<rrid>]]', 'print last request-response overview', 'pr', lambda *args: overview_handler(args, source=weber.rrdb, show_last=True)))
add_command(Command('ptrol [estu] [<rrid>[:<rrid>]]', 'print last template request-response overview', 'pr', lambda *args: overview_handler(args, source=weber.tdb, show_last=True)))

# prot
add_command(Command('prot [estu] [<rrid>[:<rrid>]]', 'print request-response pairs in tamper state', 'pr', lambda *args: overview_handler(args, source=weber.rrdb, only_tampered=True)))

# proa
add_command(Command('proa [estu] [<rrid>[:<rrid>]]', 'print request-response pairs with analysis notes', 'pr', lambda *args: overview_handler(args, source=weber.rrdb, only_with_analysis=True)))


# prX
def prx_function(_, rr, *__, **kwargs): # print detailed headers/data/both of desired requests/responses/both
    result = []
    showrequest = bool(kwargs['mask'] & 0x8)
    showresponse = bool(kwargs['mask'] & 0x4)
    showheaders = bool(kwargs['mask'] & 0x2)
    showdata = bool(kwargs['mask'] & 0x1)
    usehexdump = kwargs.get('hexdump') or False

    # deal with requests
    if showrequest:
        r = rr.request_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.request_downstream
        result += r.lines(headers=showheaders, data=showdata) if not usehexdump else hexdump(r.bytes(headers=showheaders, data=showdata))
        if showresponse:
            result.append('')
    # deal with responses
    if showresponse:
        r = rr.response_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.response_downstream
        if r is None:
            result.append('Response not received yet...')
        else:
            result += r.lines(headers=showheaders, data=showdata) if not usehexdump else hexdump(r.bytes(headers=showheaders, data=showdata))
    return result

add_command(Command('pra [<rrid>[:<rrid>]]', 'print requests-response pairs verbose', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0xf)))
add_command(Command('prh [<rrid>[:<rrid>]]', 'print request-response headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0xe)))
add_command(Command('prd [<rrid>[:<rrid>]]', 'print request-response data', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0xd)))
add_command(Command('prq [<rrid>[:<rrid>]]', 'print requests verbose', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0xb)))
add_command(Command('prqh [<rrid>[:<rrid>]]', 'print request headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0xa)))
add_command(Command('prqd [<rrid>[:<rrid>]]', 'print request data', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0x9)))
add_command(Command('prs [<rrid>[:<rrid>]]', 'print responses verbose', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0x7)))
add_command(Command('prsh [<rrid>[:<rrid>]]', 'print response headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0x6)))
add_command(Command('prsd [<rrid>[:<rrid>]]', 'print response data', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0x5)))

add_command(Command('prax [<rrid>[:<rrid>]]', 'print hexdump of requests-response pairs verbose', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0xf, hexdump=True)))
add_command(Command('prhx [<rrid>[:<rrid>]]', 'print hexdump of request-response headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0xe, hexdump=True)))
add_command(Command('prdx [<rrid>[:<rrid>]]', 'print hexdump of request-response data', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0xd, hexdump=True)))
add_command(Command('prqx [<rrid>[:<rrid>]]', 'print hexdump of requests verbose', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0xb, hexdump=True)))
add_command(Command('prqhx [<rrid>[:<rrid>]]', 'print hexdump of request headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0xa, hexdump=True)))
add_command(Command('prqdx [<rrid>[:<rrid>]]', 'print hexdump of request data', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0x9, hexdump=True)))
add_command(Command('prsx [<rrid>[:<rrid>]]', 'print hexdump of responses verbose', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0x7, hexdump=True)))
add_command(Command('prshx [<rrid>[:<rrid>]]', 'print hexdump of response headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0x6, hexdump=True)))
add_command(Command('prsdx [<rrid>[:<rrid>]]', 'print hexdump of response data', 'prX', lambda *args: foreach_rrs(prx_function, *args, mask=0x5, hexdump=True)))

add_command(Command('ptra [<rrid>[:<rrid>]]', 'print template requests-response pairs verbose', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xf)))
add_command(Command('ptrh [<rrid>[:<rrid>]]', 'print template request-response headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xe)))
add_command(Command('ptrd [<rrid>[:<rrid>]]', 'print template request-response data', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xd)))
add_command(Command('ptrq [<rrid>[:<rrid>]]', 'print template requests', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xb)))
add_command(Command('ptrqh [<rrid>[:<rrid>]]', 'print template request headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xa)))
add_command(Command('ptrqd [<rrid>[:<rrid>]]', 'print template request data', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x9)))
add_command(Command('ptrs [<rrid>[:<rrid>]]', 'print template responses', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x7)))
add_command(Command('ptrsh [<rrid>[:<rrid>]]', 'print template response headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x6)))
add_command(Command('ptrsd [<rrid>[:<rrid>]]', 'print template response data', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x5)))

add_command(Command('ptrax [<rrid>[:<rrid>]]', 'print template requests-response pairs verbose', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xf, hexdump=True)))
add_command(Command('ptrhx [<rrid>[:<rrid>]]', 'print template request-response headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xe, hexdump=True)))
add_command(Command('ptrdx [<rrid>[:<rrid>]]', 'print template request-response data', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xd, hexdump=True)))
add_command(Command('ptrqx [<rrid>[:<rrid>]]', 'print template requests', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xb, hexdump=True)))
add_command(Command('ptrqhx [<rrid>[:<rrid>]]', 'print template request headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0xa, hexdump=True)))
add_command(Command('ptrqdx [<rrid>[:<rrid>]]', 'print template request data', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x9, hexdump=True)))
add_command(Command('ptrsx [<rrid>[:<rrid>]]', 'print template responses', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x7, hexdump=True)))
add_command(Command('ptrshx [<rrid>[:<rrid>]]', 'print template response headers', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x6, hexdump=True)))
add_command(Command('ptrsdx [<rrid>[:<rrid>]]', 'print template response data', 'prX', lambda *args: foreach_rrs(prx_function, *args, fromtemplate=True, mask=0x5, hexdump=True)))

# pw 
add_command(Command('pw', 'print weber-related information', '', lambda *_: []))

# pwb
add_command(Command('pwb', 'print brute lists', 'b', b_function))

# pwm
def pwm_function(*args):
    k_len = max([len(str(k)) for k, _ in weber.mapping.l_r.items()])
    return ['    %*s <--> %s' % (k_len, k, v) for k, v in weber.mapping.l_r.items()]    
add_command(Command('pwm', 'print URI mapping', '', pwm_function))

# pwo
add_command(Command('pwo', 'print weber configuration', 'o', o_function))

# pws
def pws_function(*args):
    result = []
    files = ['    %s' % (x) for x in weber.commands['pwsf'].run()]
    if files:
        result.append('    Files:')
        result += files
    regexs = ['    %s' % (x) for x in weber.commands['pwsr'].run()]
    if regexs:
        result.append('    Regular expressions:')
        result += regexs
    return result
add_command(Command('pws', 'print spoof settings', 'pws', pws_function))

# pwsf
def pwsf_function(*args):
    return ['    %s -> %s' % (k, v) for k,v in weber.spoof_files.items()]
add_command(Command('pwsf', 'print "spoof file" settings', 'pwsf', pwsf_function))

# pwsr
def pwsr_function(*args):
    return ['    %s -> %s' % (k, v) for k,v in weber.spoof_regexs.items()]
add_command(Command('pwsr', 'print "spoof regex" settings', 'pwsr', pwsr_function))

# pwt
add_command(Command('pwt', 'print alive threads', '', lambda *_: ['    %s' % ('?' if t.remoteuri is None else t.remoteuri) for t in weber.proxy.threads]))

"""
Quit
"""
add_command(Command('q', 'quit', '', lambda *_: [])) # solved in weber



"""
Spoofing
"""
# s
add_command(Command('s', 'spoofing (alias for `pws`)', 'pws', pws_function))
add_command(Command('sf', 'print "spoof file" settings', 'pwsf', pwsf_function))
add_command(Command('sr', 'print "spoof regex" settings', 'pwsr', pwsr_function))

# sfa
def sfa_function(*args):
    try:
        uri = URI(args[0])
    except:
        log.err('Invalid URI.')
        return []
    try:
        with open(args[1], 'rb'):
            pass
    except:
        log.err('Cannot read file.')
        return []
    weber.spoof_files[uri.get_value()] = args[1]
    return []
add_command(Command('sfa <uri> <file>', 'add/modify file spoof', 'sfa', sfa_function))

# sfd
def sfd_function(*args):
    try:
        del weber.spoof_files[args[0]]
    except:
        log.err('Invalid spoof URI.')
    return []
add_command(Command('sfd <uri>', 'delete file spoof', 'sfd', sfd_function))

# sra # TODO desired also for requests?
def sra_function(*args):
    try:
        regex = ' '.join(args)
    except:
        log.err('Missing regular expression.')
        return []
    parts = tuple(split_escaped(regex[1:-1], regex[0]))
    if len(parts) != 2:
        log.err('Invalid regular expression.')
        return []
    weber.spoof_regexs[parts[0]] = parts[1]
    return []

add_command(Command('sra /old/new/', 'add/modify regex spoof', 'sra', sra_function))

# srd
def srd_function(*args):
    try:
        del weber.spoof_regexs[args[0]]
    except:
        log.err('Invalid spoof value.')
    return []
add_command(Command('srd <old>', 'delete regex spoof', 'srd', srd_function))




"""
TAMPER COMMANDS
"""
add_command(Command('t', 'tamper', 't', lambda *_: []))
add_command(Command('tr', 'tamper requests/responses', 'tr', lambda *_: []))

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
add_command(Command('trf [<rrid>[:<rrid>]]', 'forward tampered requests and responses', 'trf', lambda *args: foreach_rrs(trf_function, *args)))

# trq
def trq_function(*args):
    try:
        count = int(args[0])
    except:
        count = 1
    weber.proxy.tamper_request_counter = count
    log.info('Next %d requests will be tampered.' % (count))
    return []
add_command(Command('trq [<n>]', 'tamper next [n] request(s)', 'trq', trq_function))

# trqa
def trqa_function(*_):
    trq = not(positive(weber.config['tamper.requests'][0]))
    weber.config['tamper.requests'] = (trq, weber.config['tamper.requests'][1])
    weber.proxy.tamper_request_counter = 0
    log.info('Requests will be %s by default.' % ('TAMPERED' if trq else 'FORWARDED'))
    return []
add_command(Command('trqa', 'toggle default request tamper behavior', 'trqa', trqa_function))

# trs
def trs_function(*args):
    try:
        count = int(args[0])
    except:
        count = 1
    weber.proxy.tamper_response_counter = count
    log.info('Next %d responses will be tampered.' % (count))
    return []
add_command(Command('trs [<n>]', 'tamper next [n] response(s)', 'trs', trs_function))

# trsa
def trsa_function(*_):
    trs = not(positive(weber.config['tamper.responses'][0]))
    weber.config['tamper.responses'] = (trs, weber.config['tamper.responses'][1])
    weber.proxy.tamper_response_counter = 0
    log.info('Responses will be %s by default.' % ('TAMPERED' if trs else 'FORWARDED'))
    return []
add_command(Command('trsa', 'toggle default response tamper behavior', 'trsa', trsa_function))

# trqf
def trqf_function(_, rr, *__, **___):
    try:
        rr.request_upstream.forward()
    except:
        log.err('No request is available.')
    return []
add_command(Command('trqf [<rrid>[:<rrid>]]', 'forward tampered request', 'trqf', lambda *args: foreach_rrs(trqf_function, *args)))

# trsf
def trsf_function(_, rr, *__, **___):
    try:
        rr.response_upstream.forward()
    except: # no response
        log.info('No response is available.')
    return []
add_command(Command('trsf [<rrid>[:<rrid>]]', 'forward tampered response', 'trsf', lambda *args: foreach_rrs(trsf_function, *args)))





"""
WRITE COMMANDS
"""
# w
add_command(Command('w', 'write', 'w', lambda *_: []))
# wr
add_command(Command('wr', 'write requests/responses into file', 'wr', lambda *_: []))

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
        r = rr.request_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.request_downstream
        data += r.lines(headers=showheaders, data=showdata, as_string=False)
        if showresponse:
            data.append(b'')
    # deal with responses
    if showresponse:
        r = rr.response_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.response_downstream
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

add_command(Command('wra <file> [<rrid>[:<rrid>]]', 'write requests and responses', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, mask=0xf)))
add_command(Command('wrh <file> [<rrid>[:<rrid>]]', 'write request and response headers', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, mask=0xe)))
add_command(Command('wrd <file> [<rrid>[:<rrid>]]', 'write request and response data', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, mask=0xd)))
add_command(Command('wrq <file> [<rrid>[:<rrid>]]', 'write requests verbose', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, mask=0xb)))
add_command(Command('wrqh <file> [<rrid>[:<rrid>]]', 'write request headers', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, mask=0xa)))
add_command(Command('wrqd <file> [<rrid>[:<rrid>]]', 'write request data', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, mask=0x9)))
add_command(Command('wrs <file> [<rrid>[:<rrid>]]', 'write responses verbose', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, mask=0x7)))
add_command(Command('wrsh <file> [<rrid>[:<rrid>]]', 'write response headers', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, mask=0x6)))
add_command(Command('wrsd <file> [<rrid>[:<rrid>]]', 'write response data', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, mask=0x5)))

add_command(Command('wtra <file> [<rrid>[:<rrid>]]', 'write template requests and responses', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0xf)))
add_command(Command('wtrh <file> [<rrid>[:<rrid>]]', 'write template request and response headers', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0xe)))
add_command(Command('wtrd <file> [<rrid>[:<rrid>]]', 'write template request and response data', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0xd)))
add_command(Command('wtrq <file> [<rrid>[:<rrid>]]', 'write template requests verbose', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0xb)))
add_command(Command('wtrqh <file> [<rrid>[:<rrid>]]', 'write template request headers', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0xa)))
add_command(Command('wtrqd <file> [<rrid>[:<rrid>]]', 'write template request data', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0x9)))
add_command(Command('wtrs <file> [<rrid>[:<rrid>]]', 'write template responses verbose', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0x7)))
add_command(Command('wtrsh <file> [<rrid>[:<rrid>]]', 'write template response headers', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0x6)))
add_command(Command('wtrsd <file> [<rrid>[:<rrid>]]', 'write template response data', 'wrX', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=False, mask=0x5)))



