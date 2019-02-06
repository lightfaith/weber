#!/usr/bin/env python3
"""
Commands and config methods are implemented here.
"""

import os
import sys
import re
import traceback
import tempfile
import subprocess
from source import weber
from source import lib
from source import log
from source.docs import doc
#from source.protocols import protocols
from source.protocols.protocols import *
from source.lib import *
from source.structures import RRDB, Event, URI
from source.fd_debug import *


class Command():
    """
    Universal class for commands.
    """
    def __init__(self, command, apropos, doc_tag, function):
        """

        """
        self.command = command
        self.apropos = apropos
        if type(doc_tag) == str:
            self.doc_tag = doc_tag
            self.description = doc.get(doc_tag)
            self.description_format = lambda: {}
        elif type(doc_tag) == tuple: # result must be formatted
            self.doc_tag = doc_tag[0]
            self.description_format = doc_tag[1]
        self.function = function
    
    def __repr__(self):
        return 'Command(%s)' % (self.command)

    def __str__(self):
        return 'Command(%s)' % (self.command)

    def get_description(self):
        try:
            return doc.get(self.doc_tag).format(**self.description_format())
        except:
            return ''

    def run(self, *args):
        """
        Run command
        """
        return self.function(*args)


def add_command(command):
    """
    Function to add new command
    """
    weber.commands[command.command.partition(' ')[0]] = command

def run_command(fullcommand):
    """
    Function to run commands, apply filters etc.
    """
    modifier = weber.config['interaction.command_modifier'].value
    log.debug_command('  Fullcmd: \'%s\'' % (fullcommand))
    """split by command modifier and greppers"""
    parts = list(filter(None, re.split('(~~|~|\%s)' % (modifier), fullcommand)))
    command = parts[0]
    phase = {'~': False, '~~': False, modifier: False} # actual parsing phase
    
    """test if it is documented"""
    try:
        if not weber.commands[command.rstrip('?')].get_description().strip():
            log.warn('The command has no documentation.')
    except:
        # command does not exist, but it will be dealt in a while
        pass
    if command.endswith('?'):
        """help, not command"""
        lines = []
        for k, v in sorted(weber.commands.items(), key=lambda x:x[0]):
            length = 40
            if k == '':
                """empty command - just print long description"""
                continue
            
            if k.startswith(command[:-1]) and len(k)-len(command[:-1])<=1:
                """commands with same starting"""
                cmd, _, args = v.command.partition(' ')
                more = '' # possible question mark
                if len([x for x in weber.commands.keys() 
                        if x.startswith(cmd)])>1:
                    """add question mark after command"""
                    length += len(log.COLOR_BROWN)+len(log.COLOR_NONE)
                    more = log.COLOR_BROWN+'[?]'+log.COLOR_NONE
                """prepare apropos lines"""
                command_colored = '%s%s %s%s%s' % (cmd, more, log.COLOR_BROWN, 
                                                   args, log.COLOR_NONE)
                apropos_colored = '%s%s%s' % (log.COLOR_DARK_GREEN, v.apropos, 
                                              log.COLOR_NONE)
                lines.append('    %-*s %s' % (length, command_colored, 
                                              apropos_colored))
        if command.endswith('??'):
            """big help"""
            for k, v in weber.commands.items():
                if k == command[:-2]:
                    lines.append('')
                    lines += ['    '+log.COLOR_DARK_GREEN+line+log.COLOR_NONE 
                              for line in v.get_description().splitlines()]
    else:
        try:
            """split command into command and args"""
            command, *args = command.split(' ')
            log.debug_command('  Command: \'%s\'' % (command))
            log.debug_command('  Args:    %s' % (str(args)))
            """
            run the command
            """
            lines = weber.commands[command].run(*args)

        except Exception as e:
            log.err('Cannot execute command \''+command+'\': '+str(e)+'.')
            log.err('See traceback:')
            traceback.print_exc()
            return

    """
    Deal with resulting lines
    
    Lines can be:
        a list of strings:
            every line matching grep expression or starting with 
            '{grepignore}' will be printed
        a list of lists:
            every line of inner list matching grep expression or 
            starting with '{grepignore}' will be printed if there is 
            at least one grep matching line WITHOUT '{grepignore}'
    Reason: prsh~Set-Cookie will print all Set-Cookie lines along with 
            RRIDs, RRIDs without match are ignored
    """
    result_lines = []
    nocolor = lambda line: re.sub('\033\\[[0-9]+m', '', str(line))
    
    """go through all command parts (greps etc.) and modify lines"""
    for part in parts[1:]:
        tmp_lines = []
        if part in phase.keys():
            """special character? set phase"""
            if any(phase.values()):
                """another phase active? bad command..."""
                log.err('Invalid command.')
                return
            """no phase? set it and move on"""
            phase[part] = True
            continue
        elif not any(phase.values()):
            """no phase and no special character? bad command..."""
            log.err('Invalid command (bad regex)!')
            return
        elif phase['~']:
            """normal grep"""
            log.debug_command('  grep \'%s\'' % part)
            phase['~'] = False
            for line in lines:
                if type(line) == str:
                    if (str(line).startswith('{grepignore}') 
                            or part in nocolor(line)):
                        """str ignoring grep OR wanted value inside"""
                        tmp_lines.append(line)
                elif type(line) == list:
                    """pick groups if at least one line if
                       ignores grep or matches grep"""
                    sublines = [l for l in line 
                                if str(l).startswith('{grepignore}') 
                                or part in nocolor(l)]
                    if [x for x in sublines 
                            if not str(x).startswith('{grepignore}') 
                            and x.strip()]:
                        """found something; use matching lines"""
                        tmp_lines.append(sublines)
        elif phase['~~']:
            """regex grep"""
            log.debug_command('  regex_grep \'%s\'' % part)
            phase['~~'] = False
            for line in lines:
                if type(line) == str:
                    if (str(line).startswith('{grepignore}') 
                            or re.search(part, nocolor(line.strip()))):
                        """str ignoring grep OR wanted value inside"""
                        tmp_lines.append(line)
                elif type(line) == list:
                    """pick groups if at least one line if
                       ignores grep or matches grep"""
                    sublines = [l for l in line 
                                if str(l).startswith('{grepignore}') 
                                or re.search(part, nocolor(l.strip()))]
                    if [x for x in sublines 
                            if not str(x).startswith('{grepignore}') 
                            and x.strip()]:
                        """found something; use matching lines"""
                        tmp_lines.append(sublines)
        elif phase[modifier]:
            """modifier: less etc.""" # TODO line intervals and more features
            log.debug_command('  modification \'%s\'' % part)
            phase[modifier] = False 
            if part.endswith('L'):
                """less"""
                less_lines = []
                """find all lines to show"""
                for line in lines:
                    if type(line) == str:
                        """use returned string in less"""
                        less_lines.append(nocolor(
                            re.sub('^\\{grepignore\\}', '', line)))
                    elif type(line) == list:
                        for subline in line:
                            """ use all returned lines in less"""
                            less_lines.append(nocolor(
                                re.sub('^\\{grepignore\\}', '', subline)))
                """suppress debugs and realtime overview"""
                oldconfig = {k:weber.config[k].value 
                             for k in weber.config.keys() 
                             if k.startswith('debug.') 
                             or k == 'interaction.realtime_overview'}
                for k, _ in oldconfig.items():
                    weber.config[k].value = False
                """run less"""
                with tempfile.NamedTemporaryFile() as f:
                    f.write('\n'.join(less_lines).encode())
                    f.flush()
                    subprocess.call(['less', f.name])
                """restore debug and realtime overview settings"""
                for k, v in oldconfig.items():
                    weber.config[k].value = v
                return
        """use parsed lines for more parsing"""
        lines = tmp_lines
    """end of line parsing"""
    if any(phase.values()):
        """still in parsing phase -> wrong"""
        log.err('Invalid command.')
        return
    
    """print resulting lines"""
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

#def foreach_rrs(function, *args, fromtemplate=False, **kwargs):
def foreach_rrs(function, *args, **kwargs):
    """
    This method iterates through desired RRs and runs desired
    function on them.
    RRs are expected to be the last item of *args.
    """
    """discard empty args"""
    args = list(filter(None, args))
    result = []
    try:
        """get rrs to show"""
        desired_rrs, noproblem = weber.rrdb.get_desired_rrs(None 
                                                            if len(args)<1 
                                                            else args[-1])
        desired_rrs = desired_rrs.items()
        """remember not to send rrids to called function"""
        arg_interval = -1 if noproblem else len(args)
    except ValueError: 
        """no match"""
        return result
    except Exception as e:
        log.err('Cannot get desired rrs: %s' %  (str(e)))
        log.err('See traceback:')
        traceback.print_exc()
        desired_rrs = []

    """for each RR: prepare and run function"""
    for rrid, rr in desired_rrs:
        """create line denoting RR ID"""
        tmpresult = []
        tmpresult.append('{grepignore}%s--- #%d ---%s' % 
                         (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE))
        """
        send number of matches to the function; used by write function
        to determine whether use given path as folder
        """
        kwargs['rr_count'] = len(desired_rrs)
        """run given function"""
        tmpresult += function(rrid, rr, *args[:arg_interval], **kwargs)
        
        tmpresult.append('')
        """store result"""
        if len(list(filter(None, tmpresult)))>1:
            result.append(tmpresult)
    return result

def find_tags(_, rr, *__, **kwargs):  # rrid, rr, *args, **kwargs
    """

    """
    startends = kwargs['startends']
    attrs = kwargs.get('attrs')
    valueonly = kwargs['valueonly']
    
    if rr.response is None: # race condition, return nothing for now
        return []
    return rr.response.find_tags(startends, attrs, valueonly)
    
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #

# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #

# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
"""function to prepare specific values to main help page"""
get_help_arguments = lambda: {
    'local': weber.config['proxy.host'].value, 
    'port': weber.config['proxy.port'].value, 
    'modifier': weber.config['interaction.command_modifier'].value
}

add_command(Command('', '', ('help', get_help_arguments), lambda: []))
add_command(Command('help', 
                    'prints short intro on Weber features', 
                    ('help', get_help_arguments), 
                    lambda *_: [line for line in 
                     doc['help'].format(**get_help_arguments()).splitlines()]))

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
        c = input()
        if quit_string(c):
            break
        exec(input())
    return []

add_command(Command('prompt', 'gives python3 shell', '', prompt_function))


"""
ANALYSIS COMMANDS
"""
add_command(Command('a', 'analysis', 'a', lambda *_: []))

"""ap - print analysis packs"""
def ap_function(*args):
    result = []
    for k, v in weber.analysis.items():
        """mark enabled/disabled"""
        result.append('    %s %s' % ('+' if v['enabled'] else '-', k))
        """print rr_tests"""
        if 'rr_tests' in v.keys():
            result.append('       RR tests:')
            for testname, info, *_ in v['rr_tests']:
                result.append('        %s: %s' % (testname, info[1]))
    return result

add_command(Command('ap', 'print analysis packs', 'ap', ap_function))

"""ape, apd - enable/disable analysis pack"""
def apX_function(*args, enable):
    try:
        weber.analysis[args[0]]['enabled'] = enable
    except:
        log.err('Invalid analysis pack name.')
    return []

add_command(Command('ape <pack>', 'enable analysis pack', 'ap', 
                    lambda *args: apX_function(*args, enable=True)))
add_command(Command('apd <pack>', 'disable analysis pack', 'ap', 
                    lambda *args: apX_function(*args, enable=False)))

"""ar - print analysis results"""
def ar_function(_, rr, *__, **___):
    result = []
    for testname, severity, message, certainity in rr.analysis_notes:
        color = log.COLOR_NONE
        if severity == 'SECURITY':
            color = log.COLOR_RED
        if severity == 'WARNING':
            color = log.COLOR_YELLOW
        if severity == 'INFOLEAK':
            color = log.COLOR_CYAN
        if certainity:
            color += log.COLOR_BOLD
        result += log.info('%s<%s>%s %s: %s' % (color, 
                                                severity, 
                                                log.COLOR_NONE, 
                                                testname, 
                                                message), stdout=False)
    return result

add_command(Command('ar [<rrid>[:<rrid>]]', 
                    'print results of RR analysis', 
                    'ar', 
                    lambda *args: foreach_rrs(par_function, *args)))

"""arr - run analysis"""
def arr_function(_, rr, *__, **___):
    result = []
    rr.analyze()
    if rr.analysis_notes:
       result += ar_function(_, rr, *__, **___)
    return result

add_command(Command('arr [<rrid>[:<rrid>]]', 
                    'run RR analysis on specified request-response pairs', 
                    'arr', 
                    lambda *args: foreach_rrs(arr_function, *args)))


"""
BRUTE COMMANDS
"""
"""b - show brute-force settings"""
def b_function(*args):
    if weber.brute:
        return ['    %s:  %d values  [%s, ...] ' 
                % (weber.brute[0], 
                   len(weber.brute[1]), 
                   str(weber.brute[1][0]))]
    else:
        log.err('No dictionary loaded, see `bl`.')
        return []

add_command(Command('b', 'brute-force (alias for `pwb`)', 'b', b_function))

"""bl - load dictionary for bruteforce"""
def bl_function(*args):
    try:
        path = args[0]
        with open(path, 'rb') as f:
            weber.brute = (
                path, 
                [line.split(
                    weber.config['brute.value_separator'].value.encode()) 
                 for l in f.read().split(
                     weber.config['brute.set_separator'].value.encode())])
        return []
    except Exception as e:
        log.err('Cannot open file (%s).' % (str(e)))
        return []

add_command(Command('bl <path>', 
                    'load file for brute', 
                    ('bl', 
                     lambda: {'separator': 
                              weber.config['brute.value_separator'].value}), 
                    bl_function))

"""bfi - fault injection"""
def bfi_function(_, rr, *__, **___):
    data = rr.__bytes__()
    return [] # TODO change

add_command(Command('bfi [<rrid>[:<rrid>]]', 
                    'brute fault injection from template rrids', 
                    'bfi', 
                    lambda *args: foreach_rrs(bfi_function, 
                                              *args, 
                                              fromtemplate=True)))
"""br - / """
# NOTE only one bruter at a time can be used
add_command(Command('br', 
                    'brute from template rrid', 
                    ('br', 
                     lambda: {'placeholder': 
                              weber.config['brute.placeholder'].value}), 
                    lambda *_: []))

"""bra - brute all sets"""
# TODO refactor!
def bra_modifier(data, brute_set):
    placeholder = weber.config['brute.placeholder'][0].encode()
    for i in range(len(brute_set)):
        data = data.replace(b'%s%d%s' % (placeholder, i, placeholder), brute_set[i])
    return data
    
def bra_function(rrid, rr, *__, **___):
    """run with values"""
    if weber.brute is None: 
        log.err('No brute loaded, see `bl`.')
        return []
    max_setlen = max(len(x) for x in weber.brute[1])
    try:
        sleep = 1/int(weber.config['brute.rps'][0])
    except:
        sleep = None
    for brute_set in [x for x in weber.brute[1] if len(x) == max_setlen]:
        weber.proxy.add_connectionthread_from_template(
            rr, 
            lambda data: bra_modifier(data, brute_set))
        if sleep:
            time.sleep(sleep)
    return []

add_command(Command('bra [<rrid>[:<rrid>]]', 
                    'brute from template rrids for all sets', 
                    'br', lambda *args: foreach_rrs(bra_function, 
                                                    *args, 
                                                    fromtemplate=True)))
# TODO """brd - brute rrid until difference"""

"""rqf - forward request"""
def brf_function(_, rr, *__, **___):
    # TODO refactor
    # TODO move to rq section
    # TODO stop tampering OR create duplicate and forward
    weber.proxy.add_connectionthread_from_template(rr, lambda data: data)
    return []

add_command(Command('rqf [<rrid>[:<rrid>]]', 
                    'forward request', 
                    'rqf', 
                    lambda *args: foreach_rrs(brf_function, 
                                              *args, 
                                              fromtemplate=True)))

"""
COMPARE COMMANDS
"""
def cmp_rr_function(*args, **kwargs):
    """
    Compares 2 given RRs or any part of them.
    
    Args:   rrid1 rrid2
    Kwargs: mask:  request? response? header? data?
            forms: 1 - lines only present in first
                   2 - lines only present in second
                   c - common lines
                   d - different lines only
                   D - all lines, mark different
    """
    result = []
    """parse args"""
    try:
        rr1 = weber.rrdb.rrs[int(args[0])]
    except:
        log.err('Invalid first RRID.')
        return result
    try:
        rr2 = weber.rrdb.rrs[int(args[1])]
    except:
        log.err('Invalid second RRID.')
        return result
    
    form = kwargs['form']
    showrequest = bool(kwargs['mask'] & 0x8)
    showresponse = bool(kwargs['mask'] & 0x4)
    showheaders = bool(kwargs['mask'] & 0x2)
    showdata = bool(kwargs['mask'] & 0x1)
    
    if showrequest:
        """get request lines"""
        rrs_lines = []
        for rr in (rr1, rr2):
            rrs_lines.append(
                rr.request.lines(headers=showheaders, data=showdata))
        """diff them"""
        result += diff_lines(rrs_lines[0], rrs_lines[1])
        if showresponse:
            result.append('')

    if showresponse:
        """get response lines"""
        rrs_lines = []
        for rr in (rr1, rr2):
            r = rr.response_upstream if positive(weber.config['interaction.show_upstream'][0]) else rr.response_downstream
            if r is None:
                rrs_lines.append(['Response not received yet...'])
            else:
                rrs_lines.append(r.lines(headers=showheaders, data=showdata))
        """diff them"""
        result += diff_lines(rrs_lines[0], rrs_lines[1])
    return result

"""rac* - compare full RRs"""
add_command(Command('rac rrid1 rrid2', 
                    'compare two request-response pairs', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xf, form='D')))
add_command(Command('rac1 rrid1 rrid2', 
                    'show unique lines in first request-response pair', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xf, form='1')))
add_command(Command('rac2 rrid1 rrid2', 
                    'show unique lines in second request-response pair', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xf, form='2')))
add_command(Command('racc rrid1 rrid2', 
                    'show common lines in two request-response pairs', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xf, form='c')))
add_command(Command('racd rrid1 rrid2', 
                    'show different lines in two request-response pairs', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xf, form='d')))
"""rhc* - compare RR headers"""
add_command(Command('rhc rrid1 rrid2', 
                    'compare two request-response headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xe, form='D')))
add_command(Command('rhc1 rrid1 rrid2', 
                    'show unique lines in first request-response headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xe, form='1')))
add_command(Command('rhc2 rrid1 rrid2', 
                    'show unique lines in second request-response headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xe, form='2')))
add_command(Command('rhcc rrid1 rrid2', 
                    'show common lines in two request-response headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xe, form='c')))
add_command(Command('rhcd rrid1 rrid2', 
                    'show different lines in two request-response headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xe, form='d')))
"""rdc* - compare RR data"""
add_command(Command('rdc rrid1 rrid2', 
                    'compare two request-response data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xd, form='D')))
add_command(Command('rdc1 rrid1 rrid2', 
                    'show unique lines in first request-response data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xd, form='1')))
add_command(Command('rdc2 rrid1 rrid2', 
                    'show unique lines in second request-response data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xd, form='2')))
add_command(Command('rdcc rrid1 rrid2', 
                    'show common lines in two request-response data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xd, form='c')))
add_command(Command('rdcd rrid1 rrid2', 
                    'show different lines in two request-response data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xd, form='d')))
"""rqc* - compare requests"""
add_command(Command('rqc rrid1 rrid2', 
                    'compare two requests', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xb, form='D')))
add_command(Command('rqc1 rrid1 rrid2', 
                    'show unique lines in first request', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xb, form='1')))
add_command(Command('rqc2 rrid1 rrid2', 
                    'show unique lines in second request', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xb, form='2')))
add_command(Command('rqcc rrid1 rrid2', 
                    'show common lines in two requests', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xb, form='c')))
add_command(Command('rqcd rrid1 rrid2', 
                    'show different lines in two requests', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xb, form='d')))
"""rqhc* - compare request headers"""
add_command(Command('rqhc rrid1 rrid2', 
                    'compare two request headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xa, form='D')))
add_command(Command('rqhc1 rrid1 rrid2', 
                    'show unique lines in first request header', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xa, form='1')))
add_command(Command('rqhc2 rrid1 rrid2', 
                    'show unique lines in second request header', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xa, form='2')))
add_command(Command('rqhcc rrid1 rrid2', 
                    'show common lines in two request headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xa, form='c')))
add_command(Command('rqhcd rrid1 rrid2', 
                    'show different lines in two request headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0xa, form='d')))
"""rqdc* - compare request data"""
add_command(Command('rqdc rrid1 rrid2', 
                    'compare two request data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x9, form='D')))
add_command(Command('rqdc1 rrid1 rrid2', 
                    'show unique lines in first request data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x9, form='1')))
add_command(Command('rqdc2 rrid1 rrid2', 
                    'show unique lines in second request data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x9, form='2')))
add_command(Command('rqdcc rrid1 rrid2', 
                    'show common lines in two request data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x9, form='c')))
add_command(Command('rqdcd rrid1 rrid2', 
                    'show different lines in two request data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x9, form='d')))
"""rsc* - compare responses"""
add_command(Command('rsc rrid1 rrid2', 
                    'compare two responses', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x7, form='D')))
add_command(Command('rsc1 rrid1 rrid2', 
                    'show unique lines in first response', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x7, form='1')))
add_command(Command('rsc2 rrid1 rrid2', 
                    'show unique lines in second response', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x7, form='2')))
add_command(Command('rscc rrid1 rrid2', 
                    'show common lines in two responses', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x7, form='c')))
add_command(Command('rscd rrid1 rrid2', 
                    'show different lines in two responses', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x7, form='d')))
"""rshc* - compare response headers"""
add_command(Command('rshc rrid1 rrid2', 
                    'compare two response headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x6, form='D')))
add_command(Command('rshc1 rrid1 rrid2', 
                    'show unique lines in first response header', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x6, form='1')))
add_command(Command('rshc2 rrid1 rrid2', 
                    'show unique lines in second response header', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x6, form='2')))
add_command(Command('rshcc rrid1 rrid2', 
                    'show common lines in two response headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x6, form='c')))
add_command(Command('rshcd rrid1 rrid2', 
                    'show different lines in two response headers', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x6, form='d')))
"""rsdc* - compare response data"""
add_command(Command('rsdc rrid1 rrid2', 
                    'compare two response data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x5, form='D')))
add_command(Command('rsdc1 rrid1 rrid2', 
                    'show unique lines in first response data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x5, form='1')))
add_command(Command('rsdc2 rrid1 rrid2', 
                    'show unique lines in second response data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x5, form='2')))
add_command(Command('rsdcc rrid1 rrid2', 
                    'show common lines in two response data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x5, form='c')))
add_command(Command('rsdcd rrid1 rrid2', 
                    'show different lines in two response data', 
                    'compare_rr', 
                    lambda *args: cmp_rr_function(*args, mask=0x5, form='d')))






"""
EVENT COMMANDS
"""
# TODO refactor from scratch
#e    print events     
#ea     create event, define type
#era    add RRs into event 
#erD    delete RRs from event
#eD      destroy event, keep rrs in default
#es   select actual event
'''
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
'''














"""
MODIFY COMMANDS
"""
# TODO refactor
#rD     delete RR 
#rqC     clone rq
#rqm   - as mrq; duplicate if not tamper
#rsm   - as mrs; only if tamper
'''
add_command(Command('m', 'modify', 'm', lambda *_: []))
add_command(Command('mt', 'modify template', 'mr', lambda *_: []))
add_command(Command('mtr', 'modify template request/response', 'mr', lambda *_: []))
add_command(Command('mr', 'modify request/response', 'mr', lambda *_: []))
def mr_function(*args, fromtemplate=False, force_template_creation=False):
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

        if (not r.tampering and not fromtemplate) or force_template_creation:
            # create template from RR
            tid = weber.tdb.add_rr(weber.rrdb.rrs[rrid].clone(), update_rr_rrid=True)
            log.info('Creating template #%d from RR #%d...' % (tid, rrid))
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
    if changes != r.bytes() or force_template_creation:
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
        
add_command(Command('mrq <rrid>', 'modify request', 'mr', lambda *args: mr_function('request', *args)))
add_command(Command('mrs <rrid>', 'modify response', 'mr', lambda *args: mr_function('response', *args)))
add_command(Command('mrq! <rrid>', 'create template from request and modify', 'mr', lambda *args: mr_function('request', *args, force_template_creation=True)))
add_command(Command('mrs! <rrid>', 'create template from response and modify', 'mr', lambda *args: mr_function('response', *args, force_template_creation=True)))
add_command(Command('mtrq <rrid>', 'modify template request', 'mr', lambda *args: mr_function('request', *args, fromtemplate=True)))
add_command(Command('mtrs <rrid>', 'modify template response', 'mr', lambda *args: mr_function('response', *args, fromtemplate=True)))
'''











"""
OPTIONS COMMANDS
"""
# TODO add to weber section
"""wo - show options"""
def wo_function(*_):
    lines = []
    for k,v in weber.config.items():
        lines.append('    %-30s  %s' % (k, v.get_text_value()))
    return lines

add_command(Command('wo', 'print Weber options', 'wo', wo_function))

"""wos - set an option"""
def wos_function(*args):
    """parse key and value"""
    try:
        key = args[0]
        value = args[1]
    except:
        log.err('Invalid arguments.')
        return []
    """try to set || create new"""
    try:
        weber.config[key].value = value
    except:
        """create user-defined with @"""
        key = key if key.startswith('@') else '@%s' % key
        weber.config[key] = Option(value, data_type)
    return []

add_command(Command('wos <key> <value>', 
                    'change Weber configuration', 
                    'wo', 
                    wos_function))

"""rc - print Cookie headers in requests"""
def rc_function(_, rr, *__, **___):
    try:
        cookies = rr.request.headers[b'Cookie'].split(b';')
        cookies = dict([tuple(c.split(b'=')) for c in cookies])
        maxlen = max([0]+[len(k.decode().strip()) for k in cookies.keys()])
        return ['%*s: %s' % (maxlen, k.decode().strip(), v.decode()) 
                for k,v in cookies.items()]
    except:
        return []

add_command(Command('rc [<rrid>[:<rrid>]]', 
                    'print cookies sent in requests', 
                    'rc', 
                    lambda *args: foreach_rrs(rc_function, *args)))

"""rcs - print Set-Cookie headers in responses"""
def rcs_function(_, rr, *__, **___):
    try:
        cookies = rr.response.headers[b'Set-Cookie'].split(b';')
        attrs = dict([(tuple(c.strip().split(b'=')+[b''])[:2]) 
                      for c in cookies])
        maxlen = max([0]+[len(k.decode()) for k in attrs.keys()])
        return ['%*s%s' 
                % (maxlen, k.decode(), (': '+v.decode() if v else '')) 
                for k,v in attrs.items()]
    except:
        #traceback.print_exc()
        return []
add_command(Command('rcs [<rrid>[:<rrid>]]', 
                    'print cookies set in reqponses', 
                    'rcs', lambda *args: foreach_rrs(rcs_function, *args)))

#add_command(Command('pe [<eid>[:<eid>]]', 'print events', 'e', e_function))

# rH - only relevant for HTTP
if 'source.protocols.http' in sys.modules.keys():
    add_command(Command('rH', 'print HTML-related info', 'ph', lambda *_: []))

    """rHc - print HTML comments"""
    add_command(Command('rHc [<rrid>[:<rrid>]]', 
                        'print HTML comments', 
                        'rHc', 
                        lambda *args: foreach_rrs(
                            find_tags, 
                            *args, 
                            startends=[(b'<!--', b'-->')], 
                            valueonly=False)))

    """rHf - print HTML forms"""
    add_command(Command('rHf [<rrid>[:<rrid>]]', 
                        'print HTML forms', 
                        'rHf', 
                        lambda *args: foreach_rrs(
                            find_tags, 
                            *args, 
                            startends=[(b'<form', b'</form>')], 
                            valueonly=False)))

    """rHl - print hyperlinks"""
    add_command(
        Command(
            'rHl [<rrid>[:<rrid>]]', 
            'print HTML links', 
            'rHl', 
            lambda *args: foreach_rrs(
                find_tags, 
                *args, 
                startends=[x[:2] for x in 
                           sys.modules['source.protocols.http'].HTTP.link_tags], 
                attrs=[x[2] for x in 
                       sys.modules['source.protocols.http'].HTTP.link_tags], 
                valueonly=True)))
    
    """rHlc - print hyperlinks with context"""
    add_command(
        Command(
            'rHlc [<rrid>[:<rrid>]]', 
            'print HTML links with context', 
            'rHlc', 
            lambda *args: foreach_rrs(
                find_tags, 
                *args, 
                startends=[x[:2] for x in 
                           sys.modules['source.protocols.http'].HTTP.link_tags], 
                attrs=[x[2] for x in 
                       sys.modules['source.protocols.http'].HTTP.link_tags], 
                valueonly=False)))
    #add_command(Command('phlc [<rrid>[:<rrid>]]', 'print links with context', 'phlc', lambda *args: foreach_rrs(find_tags, *args, startends=[x[:2] for x in sys.modules['source.protocols.http'].HTTP.link_tags], valueonly=False)))

    """rHm - print <main> elements"""
    add_command(Command('phm [<rrid>[:<rrid>]]', 
                        'print <main> elements', 
                        'phm', 
                        lambda *args: foreach_rrs(
                            find_tags, 
                            *args, 
                            startends=[(b'<main', b'</main>')], 
                            valueonly=False)))

    """rHs - search in HTML"""
    add_command(Command('rHs <start> <end>', 
                        'search in HTML', 
                        'phm', 
                        lambda *args: foreach_rrs(
                            find_tags, 
                            *args, 
                            startends=[(args[0].encode(), args[1].encode())], 
                            valueonly=False)))

"""rp - print request parameters"""
def rp_function(_, rr, *__, **___):
    maxlen = max([0]+[len(k) for k in rr.request.parameters.keys()])
    return ['%*s: %s' % (maxlen, k.decode(), v.decode() if v else '') 
            for k, v in r.parameters.items()]

add_command(Command('rp [<rrid>[:<rrid>]]', 
                    'print HTTP parameters', 
                    'rp', 
                    lambda *args: foreach_rrs(rp_function, *args)))

"""overview
overview is defined in structures.py because it is also used by proxy 
(realtime overview)"""
def overview_handler(
        args, 
        show_last=False, 
        only_tampered=False, 
        only_with_analysis=False):
    """decide what columns to show"""
    show_event = False
    show_size = False
    show_time = False
    show_uri = False
    """some modifiers (defaults are considered in overview() function)"""
    if args and re.match('^[estu]+$', args[0]): 
        show_event = 'e' in args[0]
        show_size = 's' in args[0]
        show_time = 't' in args[0]
        show_uri = 'u' in args[0]
        args = args[1:]
    """show overview"""
    return weber.rrdb.overview(
        args, 
        show_event=show_event, 
        show_size=show_size, 
        show_time=show_time, 
        show_uri=show_uri, 
        show_last=show_last, 
        only_tampered=only_tampered, 
        only_with_analysis=only_with_analysis)

add_command(Command('r [estu] [<rrid>[:<rrid>]]', 
                    'print request-response overview (alias for `ro`)', 
                    'r', 
                    lambda *args: overview_handler(args)))

add_command(Command('ro [estu] [<rrid>[:<rrid>]]', 
                    'print request-response overview', 
                    'r', 
                    lambda *args: overview_handler(args)))
"""rol - overview of last 10"""
add_command(Command('rol [estu] [<rrid>[:<rrid>]]', 
                    'print last request-response overview', 
                    'r', 
                    lambda *args: overview_handler(args, show_last=True)))
"""rot - overview of tampering"""
add_command(Command('rot [estu] [<rrid>[:<rrid>]]', 
                    'print request-response pairs in tampering state', 
                    'r', 
                    lambda *args: overview_handler(args, only_tampered=True)))

"""roa - overview of RRs with analysis notes"""
add_command(Command('roa [estu] [<rrid>[:<rrid>]]', 
                    'print request-response pairs with analysis notes', 
                    'r', 
                    lambda *args: overview_handler(args, 
                                                   only_with_analysis=True)))

""" rX detailed print of X"""
def rx_function(_, rr, *__, **kwargs): 
    result = []
    showrequest = bool(kwargs['mask'] & 0x8)
    showresponse = bool(kwargs['mask'] & 0x4)
    showheaders = bool(kwargs['mask'] & 0x2)
    showdata = bool(kwargs['mask'] & 0x1)
    usehexdump = kwargs.get('hexdump') or False

    """deal with requests"""
    if showrequest:
        result += (rr.request.lines(headers=showheaders, data=showdata) 
                   if not usehexdump else 
                   hexdump(rr.request.bytes(headers=showheaders, 
                                            data=showdata)))
        if showresponse:
            result.append('')
    """deal with responses"""
    if showresponse:
        if not rr.response:
            result.append('Response not received yet...')
        else:
            result += (rr.response.lines(headers=showheaders, data=showdata) 
                       if not usehexdump 
                       else hexdump(rr.response.bytes(headers=showheaders, 
                                                      data=showdata)))
    return result

add_command(Command('ra [<rrid>[:<rrid>]]', 
                    'print requests-response pairs verbose', 
                    'rX', 
                    lambda *args: foreach_rrs(rx_function, *args, mask=0xf)))
add_command(Command('rh [<rrid>[:<rrid>]]', 
                    'print request-response headers', 
                    'rX', 
                    lambda *args: foreach_rrs(rx_function, *args, mask=0xe)))
add_command(Command('rd [<rrid>[:<rrid>]]', 
                    'print request-response data', 
                    'rX', 
                    lambda *args: foreach_rrs(rx_function, *args, mask=0xd)))
add_command(Command('rq [<rrid>[:<rrid>]]', 
                    'print requests verbose', 
                    'rX', 
                    lambda *args: foreach_rrs(rx_function, *args, mask=0xb)))
add_command(Command('rqh [<rrid>[:<rrid>]]',
                    'print request headers', 
                    'rX', 
                    lambda *args: foreach_rrs(rx_function, *args, mask=0xa)))
add_command(Command('rqd [<rrid>[:<rrid>]]', 
                    'print request data', 
                    'rX', 
                    lambda *args: foreach_rrs(rx_function, *args, mask=0x9)))
add_command(Command('rs [<rrid>[:<rrid>]]', 
                    'print responses verbose', 
                    'rX', 
                    lambda *args: foreach_rrs(rx_function, *args, mask=0x7)))
add_command(Command('rsh [<rrid>[:<rrid>]]', 
                    'print response headers', 
                    'rX', 
                    lambda *args: foreach_rrs(rx_function, *args, mask=0x6)))
add_command(Command('rsd [<rrid>[:<rrid>]]', 
                    'print response data', 
                    'rX', 
                    lambda *args: foreach_rrs(rx_function, *args, mask=0x5)))

add_command(Command('rax [<rrid>[:<rrid>]]',
                    'print hexdump of requests-response pairs verbose', 
                    'rX', 
                    lambda *args: foreach_rrs(
                        rx_function, *args, mask=0xf, hexdump=True)))
add_command(Command('rhx [<rrid>[:<rrid>]]',
                    'print hexdump of request-response headers', 
                    'rX', 
                    lambda *args: foreach_rrs(
                        rx_function, *args, mask=0xe, hexdump=True)))
add_command(Command('rdx [<rrid>[:<rrid>]]', 
                    'print hexdump of request-response data', 
                    'rX', 
                    lambda *args: foreach_rrs(
                        rx_function, *args, mask=0xd, hexdump=True)))
add_command(Command('rqx [<rrid>[:<rrid>]]',
                    'print hexdump of requests verbose', 
                    'rX', 
                    lambda *args: foreach_rrs(
                        rx_function, *args, mask=0xb, hexdump=True)))
add_command(Command('rqhx [<rrid>[:<rrid>]]',
                    'print hexdump of request headers', 
                    'rX', 
                    lambda *args: foreach_rrs(
                        rx_function, *args, mask=0xa, hexdump=True)))
add_command(Command('rqdx [<rrid>[:<rrid>]]', 
                    'print hexdump of request data', 
                    'rX', 
                    lambda *args: foreach_rrs(
                        rx_function, *args, mask=0x9, hexdump=True)))
add_command(Command('rsx [<rrid>[:<rrid>]]', 
                    'print hexdump of responses verbose', 
                    'rX', 
                    lambda *args: foreach_rrs(
                        rx_function, *args, mask=0x7, hexdump=True)))
add_command(Command('rshx [<rrid>[:<rrid>]]', 
                    'print hexdump of response headers', 
                    'rX', 
                    lambda *args: foreach_rrs(
                        rx_function, *args, mask=0x6, hexdump=True)))
add_command(Command('rsdx [<rrid>[:<rrid>]]', 
                    'print hexdump of response data', 
                    'rX', 
                    lambda *args: foreach_rrs(
                        rx_function, *args, mask=0x5, hexdump=True)))

"""w - Weber stuff """ # TODO move to Weber section 
add_command(Command('w', 'Weber-related information', 'w', lambda *_: []))

# pwb
#add_command(Command('pwb', 'print brute lists', 'b', b_function))

'''
# pwm
def pwm_function(*args):
    k_len = max([len(str(k)) for k, _ in weber.mapping.l_r.items()])
    return ['    %*s <--> %s' % (k_len, k, v) for k, v in weber.mapping.l_r.items()]    
add_command(Command('pwm', 'print URI mapping', 'pwm', pwm_function))
'''

"""ws - print spoof settings"""
def get_spoof_regexs(requests=True, responses=True):
    result = []
    if requests:
        result +=  ['    %s -> %s' % (k, v) 
                    for k,v in weber.spoof_request_regexs.items()]
    if responses:
        result +=  ['    %s -> %s' % (k, v) 
                    for k,v in weber.spoof_response_regexs.items()]
    return result

def ws_function(*args):
    result = []
    files = ['    %s' % (x) for x in weber.commands['pwsf'].run()]
    if files:
        result.append('    Files:')
        result += files

    request_regexs = ['    %s' % (x) for x in get_spoof_regexs(responses=False)]
    if request_regexs:
        result.append('    Regular expressions for requests:')
        result += request_regexs
    
    response_regexs = ['    %s' % (x) for x in get_spoof_regexs(requests=False)]
    if response_regexs:
        result.append('    Regular expressions for responses:')
        result += response_regexs

    return result

add_command(Command('ws', 'print spoof settings', 'ws', ws_function))

"""rssf - print file spoof settings"""
def rssf_function(*args):
    return ['    %s -> %s' % (k, v) for k,v in weber.spoof_files.items()]

add_command(Command('rssf', 
                    'print "spoof file" settings', 
                    'rssf', 
                    rssf_function))

"""rqs - print request regex spoof settings"""
add_command(Command('rqs', 
                    'print "spoof request regex" settings', 
                    'rqs', 
                    lambda *_: get_spoof_regexs(responses=False)))

"""rss - print response regex spoof settings"""
add_command(Command('rss', 
                    'print response "spoof regex" settings', 
                    'rss', 
                    lambda *_: get_spoof_regexs(requests=False)))

"""wt - print alive threads"""
add_command(Command('wt', 
                    'print alive threads', 
                    'wt', 
                    lambda *_: ['    %s' 
                                % (t.server.uri if t.server else '?') 
                                for t in weber.proxy.threads]))
"""
Quit
"""
"""q - quit (solved in /weber)"""
add_command(Command('q', 'quit', 'q', lambda *_: []))

'''
"""
Spoofing
"""
# s
add_command(Command('s', 'spoofing (alias for `pws`)', 'pws', pws_function))
add_command(Command('sf', 'print "spoof file" settings', 'sf', pwsf_function))
add_command(Command('sr', 'print "spoof regex" settings', 'sr', lambda *_: get_spoof_regexs()))
add_command(Command('srq', 'print "spoof request regex" settings (alias for `pwsrq`)', 'sr', lambda *_: get_spoof_regexs(responses=False)))
add_command(Command('srs', 'print "spoof response regex" settings (alias for `pwsrs`)', 'sr', lambda *_: get_spoof_regexs(requests=False)))
'''
"""rssfa - add file spoof"""
def rssfa_function(*args):
    args = list(filter(None, args))
    try:
        uri = URI(args[0])
    except:
        log.err('Invalid URI.')
        return []
    try:
        with open(args[1], 'rb'):
            pass
    except:
        traceback.print_exc()
        log.err('Cannot read file.')
        return []
    weber.spoof_files[uri.get_value()] = args[1]
    return []
add_command(Command('rssfa <uri> <file>', 
                    'add/modify file spoof', 
                    'sf', 
                    rssfa_function))

"""rssfD - delete file spoof"""
def rssfD_function(*args):
    try:
        del weber.spoof_files[args[0]]
    except:
        log.err('Invalid spoof URI.')
    return []
add_command(Command('rssfD <uri>', 
                    'delete file spoof', 
                    'sf', 
                    rssfD_function))

"""rXsa - add regex spoof""" 
def srXa_function(*args, spoof_dict=None):
    try:
        regex = ' '.join(args)
    except:
        log.err('Missing regular expression.')
        return []
    try:
        parts = tuple(split_escaped(regex[1:-1], regex[0]))
    except:
        log.err('Invalid regular expression.')
        return []
    if len(parts) != 2:
        log.err('Invalid regular expression.')
        return []
    """add spoof entry"""
    try:
        spoof_dict[parts[0]] = parts[1]
    except:
        log.err('Invalid regex dictionary.')

    return []

add_command(Command('rqsa /old/new/', 
                    'add/modify regex spoof for requests', 
                    'rXsa', 
                    lambda *args: srXa_function(
                        *args, spoof_dict=weber.spoof_request_regexs)))

add_command(Command('rssa /old/new/', 
                    'add/modify regex spoof for responses', 
                    'rXsa', 
                    lambda *args: srXa_function(
                        *args, spoof_dict=weber.spoof_response_regexs)))

"""rXsD - remove regex spoof"""
def rXsD_function(*args, spoof_dict=None):
    try:
        del spoof_dict[args[0]]
    except TypeError:
        log.err('Invalid regex dictionary.')
    except:
        log.err('Invalid spoof value.')
    return []

add_command(Command('rqsD <old>', 
                    'delete request regex spoof', 
                    'rXsD', 
                    lambda *args: rXsD_function(
                        *args, spoof_dict=weber.spoof_request_regexs)))
add_command(Command('rssD <old>', 
                    'delete response regex spoof', 
                    'rXsD', 
                    lambda *args: srXd_function(
                        *args, spoof_dict=weber.spoof_response_regexs)))




"""
TAMPER COMMANDS
"""
add_command(Command('t', 'tamper', 't', lambda *_: []))
add_command(Command('tr', 'tamper requests/responses', 't', lambda *_: []))

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


# wf 
def wf_function(*args):
    csp = weber.config['crawl.save_path']
    try:
        weber.config['crawl.save_path'] = (args[0], csp[1])
        log.info('Downloaded data will be saved at %s.' % args[0])
    except:
        weber.config['crawl.save_path'][0] = ('', csp[1])
        log.info('Response data will not be autosaved.')
    return []
add_command(Command('wf [<path>]', 'auto-save response content in given location', 'wf', wf_function))


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

add_command(Command('wra <file> [<rrid>[:<rrid>]]', 'write requests and responses', 'wr', lambda *args: foreach_rrs(wrx_function, *args, mask=0xf)))
add_command(Command('wrh <file> [<rrid>[:<rrid>]]', 'write request and response headers', 'wr', lambda *args: foreach_rrs(wrx_function, *args, mask=0xe)))
add_command(Command('wrd <file> [<rrid>[:<rrid>]]', 'write request and response data', 'wr', lambda *args: foreach_rrs(wrx_function, *args, mask=0xd)))
add_command(Command('wrq <file> [<rrid>[:<rrid>]]', 'write requests verbose', 'wr', lambda *args: foreach_rrs(wrx_function, *args, mask=0xb)))
add_command(Command('wrqh <file> [<rrid>[:<rrid>]]', 'write request headers', 'wr', lambda *args: foreach_rrs(wrx_function, *args, mask=0xa)))
add_command(Command('wrqd <file> [<rrid>[:<rrid>]]', 'write request data', 'wr', lambda *args: foreach_rrs(wrx_function, *args, mask=0x9)))
add_command(Command('wrs <file> [<rrid>[:<rrid>]]', 'write responses verbose', 'wr', lambda *args: foreach_rrs(wrx_function, *args, mask=0x7)))
add_command(Command('wrsh <file> [<rrid>[:<rrid>]]', 'write response headers', 'wr', lambda *args: foreach_rrs(wrx_function, *args, mask=0x6)))
add_command(Command('wrsd <file> [<rrid>[:<rrid>]]', 'write response data', 'wr', lambda *args: foreach_rrs(wrx_function, *args, mask=0x5)))

add_command(Command('wtra <file> [<rrid>[:<rrid>]]', 'write template requests and responses', 'wr', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=True, mask=0xf)))
add_command(Command('wtrh <file> [<rrid>[:<rrid>]]', 'write template request and response headers', 'wr', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=True, mask=0xe)))
add_command(Command('wtrd <file> [<rrid>[:<rrid>]]', 'write template request and response data', 'wr', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=True, mask=0xd)))
add_command(Command('wtrq <file> [<rrid>[:<rrid>]]', 'write template requests verbose', 'wr', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=True, mask=0xb)))
add_command(Command('wtrqh <file> [<rrid>[:<rrid>]]', 'write template request headers', 'wr', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=True, mask=0xa)))
add_command(Command('wtrqd <file> [<rrid>[:<rrid>]]', 'write template request data', 'wr', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=True, mask=0x9)))
add_command(Command('wtrs <file> [<rrid>[:<rrid>]]', 'write template responses verbose', 'wr', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=True, mask=0x7)))
add_command(Command('wtrsh <file> [<rrid>[:<rrid>]]', 'write template response headers', 'wr', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=True, mask=0x6)))
add_command(Command('wtrsd <file> [<rrid>[:<rrid>]]', 'write template response data', 'wr', lambda *args: foreach_rrs(wrx_function, *args, fromtemplate=True, mask=0x5)))




# ww
def ww_function(*args):
    try:
        dump_file = args[0]
    except:
        log.err('No output file specified.')
        return []
    import pickle
    # TODO with dump_lock?
    
    if [rr for db in [weber.rrdb, weber.tdb] for _,rr in db.rrs.items() if rr.request_upstream.tampering or rr.response_upstream.tampering]:
        log.err('Cannot dump session if tampering is in progress.')
        return []
    
    log.info('Dumping session into \'%s\'...' % dump_file)
    weber.rrdb.lock = None
    weber.tdb.lock = None
    weber.mapping.lock = None
    data = (
        weber.proxy.init_target, 
        weber.config,
        #weber.protocols,
        #weber.commands,
        weber.rrdb,
        weber.tdb,
        weber.mapping,
        weber.events,
        weber.spoof_files,
        weber.spoof_request_regexs,
        weber.spoof_response_regexs,
        weber.brute,
        weber.forward_fail_uris,
        #weber.analysis,
        weber.servers,
    )
    with open(dump_file, 'wb') as f:
        pickle.dump(data, f)
        
    weber.rrdb.setup_lock()
    weber.tdb.setup_lock()
    weber.mapping.setup_lock()
    return []
add_command(Command('ww <file>', 'dump Weber session into file', 'ww', ww_function))

