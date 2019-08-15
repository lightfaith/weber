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
    parts = list(filter(None, re.split(r'(~~|~|\%s)' % (modifier), fullcommand)))
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
            length = 50
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
        #desired_rrs, noproblem = weber.rrdb.get_desired_rrs(None 
        #                                                    if len(args)<1 
        #                                                    else args[-1])
        #desired_rrs = desired_rrs.items()
        fails = []
        desired_rrs = weber.rrdb.get_desired_rrs((args[-1] 
                                                  if args 
                                                  else None),
                                                 fails=fails).items()
        """remember not to send rrids to called function"""
        arg_interval = -1 if fails else len(args)
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
    '''for o in weber.config.keys():
        if o.startswith('debug'):
            weber.config[o].value = True
    '''
    #print('random in threads:', [t.request.random_number for t in weber.proxy.threads])
    #print(weber.proxy.threads[0].request.lines())
    #print('random in rrdb:   ', [rr.request.random_number for rr in weber.rrdb.rrs.values()])
    #print(list(weber.rrdb.rrs.values())[0].request.lines())
    for rr in weber.rrdb.rrs.values():
        print(rr.rrid)
        print(rr.times)
        print()
    '''for server in weber.servers:
        result.append(str(server.uri))
        result.append(str(server.rrs))
        result.append('')'''
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
                [l.split(
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
'''
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
'''

def bra_function(rrid, rr, *__, **___):
    #if not weber.brute:
    #    log.err('No brute loaded, see `bl`.')
    #    return []
    weber.proxy.brute(rrid)
    return []

add_command(Command('bra [<rrid>[:<rrid>]]', 
                    'brute from template rrids for all sets', 
                    'br', lambda *args: foreach_rrs(bra_function, 
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
        result += diff_lines(rrs_lines[0], rrs_lines[1], form)
        if showresponse:
            result.append('')

    if showresponse:
        """get response lines"""
        rrs_lines = []
        for rr in (rr1, rr2):
            r = rr.response
            if r is None:
                rrs_lines.append(['Response not received yet...'])
            else:
                rrs_lines.append(r.lines(headers=showheaders, data=showdata))
        """diff them"""
        result += diff_lines(rrs_lines[0], rrs_lines[1], form)
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
    #for rrid, rr in weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1])[0].items():
    for rrid, rr in weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1]).items():
        rr.eid = eid
        weber.events[eid].rrids.add(rrid)
    return []
add_command(Command('ea eid <rrid>[:<rrid>]', 'adds requests/responses into event', 'ea', ea_function))

def ed_function(*args):
    #for rrid, rr in weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1])[0].items():
    for rrid, rr in weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1]).items():
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
#rqm   - as mrq; duplicate if not tamper
#rsm   - as mrs; only if tamper
# TODO rqms - change server
def mr_function(*args):
    """parse command arguments"""
    duplicate = False
    try:
        rrid = int(args[1])
        rr = weber.rrdb.rrs[rrid]
        if args[0] == 'request':
            r = rr.request
            if not r.tampering:
                duplicate = True
        elif args[0] == 'response':
            r = rr.response
            if not r.tampering:
                log.err('Cannot modify finished response.')
                return []
        else:
            log.err('Invalid type.')
            return []
    except:
        log.err('Invalid RRID.')
        #traceback.print_exc()
        return []
    if not r:
        log.err('Non-existent %s for RRID #%d.' % (args[0], rrid))
        return []

    """duplicate?"""
    if duplicate:
        _, rrid, r = weber.proxy.duplicate(rrid, force_tamper_request=True)

    """suppress debugs and realtime overview"""
    oldconfig = {k:weber.config[k].value 
                 for k in weber.config.keys() 
                 if k.startswith('debug.') 
                 or k == 'interaction.realtime_overview'}
    for k, _ in oldconfig.items():
        weber.config[k].value = False
    """write into temp file, open with desired editor"""
    with tempfile.NamedTemporaryFile() as f:
        f.write(r.bytes())
        f.flush()
        subprocess.call((weber.config['edit.command'].value % (f.name)).split())
        f.seek(0)
        """read back"""
        changes = f.read()
    """restore debug and realtime overview settings"""
    for k, v in oldconfig.items():
        weber.config[k].value = v
    """write if changed"""
    log.debug_tampering('%s has been edited.' % args[0].title())
    r.original = changes
    r.parse()
    r.pre_tamper()
    log.tprint(' '.join(weber.rrdb.overview([str(rrid)], header=False)))
    '''if changes != r.bytes():
        log.debug_tampering('%s has been edited.' % args[0].title())
        r.original = changes
        r.parse()
        r.pre_tamper()
    else:
        log.debug_tampering('No change in the %s.' % args[0])
        """delete template if just created""" 
    '''
    return []
        
add_command(Command('rqm <rrid>', 
                    'modify request', 
                    'mr', # TODO
                    lambda *args: mr_function('request', *args)))
add_command(Command('rsm <rrid>', 
                    'modify response', 
                    'mr',  # TODO
                    lambda *args: mr_function('response', *args)))

"""rD - delete RRs in event"""
# TODO what about delete in server?
def rD_function(rrid, rr, *_, **__):
    """stop if running thread"""
    matching_threads = [t for t in weber.proxy.threads if t.rrid == rrid]
    for t in matching_threads:
        t.stop()
    """force clean"""
    weber.proxy.clean_threads()
    """delete from RRDB"""
    # TODO only for actual event
    try:
        del weber.rrdb.rrs[rrid]
    except:
        log.err('No RR #%d in database.' % rrid)
    return []

add_command(Command('rD [<rrid>[:<rrid>]]', 
                    'delete requests/responses', 
                    'rD', 
                    lambda *_: foreach_rrs(rD_function, *_))) # TODO by event











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
        weber.config[key] = weber.Option(value, str)
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
            for k, v in rr.request.parameters.items()]

add_command(Command('rp [<rrid>[:<rrid>]]', 
                    'print HTTP parameters', 
                    'rp', 
                    lambda *args: foreach_rrs(rp_function, *args)))

"""rt - print timelines"""
def rt_function(_, rr, *__, **___):
    result = ['%20s %s' % (k+':', v) for k,v in rr.times.items()]
    # TODO some style, maybe delta?
    # or more statistics? (server, MIME, size, ...)
    return result
add_command(Command('rt [<rrid>[:<rrid>]]', 
                    'print request/response timeline', 
                    'rt', # TODO 
                    lambda *args: foreach_rrs(rt_function, *args)))

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
        result += (rr.request.lines(headers=showheaders, 
                                    data=showdata, 
                                    splitter=b'\n') 
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
            result += (rr.response.lines(headers=showheaders, 
                                         data=showdata,
                                         splitter=b'\n') 
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
    files = ['    %s' % (x) for x in weber.commands['rssf'].run()]
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
                    'rXs', 
                    lambda *_: get_spoof_regexs(responses=False)))

"""rss - print response regex spoof settings"""
add_command(Command('rss', 
                    'print response "spoof regex" settings', 
                    'rXs', 
                    lambda *_: get_spoof_regexs(requests=False)))

"""wt - print alive threads"""
def wt_function(*_):
    weber.proxy.clean_threads()
    #return ['    %s' % (t.full_uri or '?') for t in weber.proxy.threads]
    return ['    %s' % str(t) for t in weber.proxy.threads]
add_command(Command('wt', 
                    'print alive threads', 
                    'wt', 
                    wt_function))
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
    weber.spoof_files[uri.tostring()] = args[1]
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
REPLAY COMMANDS
"""
def rqr_function(rrid, _, *__, **___):
    weber.proxy.duplicate(rrid)
    return []

add_command(Command('rqr [<rrid>[:<rrid>]]', 
                    'replay request', 
                    'rqr',  # TODO
                    lambda *args: foreach_rrs(rqr_function, *args)))

def rqrm_function(rrid, rr, *__, **___):
    for method in weber.config['http.replay_methods'].value.encode().split():
        if rr.request.method == method:
            continue
        t, rrid, r = weber.proxy.duplicate(rrid, force_tamper_request=True)
        r.method = method
        t.force_tamper_request = False
        t.try_forward_tamper()
    return []

add_command(Command('rqrm [<rrid>[:<rrid>]]', 
                    'replay request with different methods',
                    'rqrm', # TODO
                    lambda *args: foreach_rrs(rqrm_function, *args)))

"""
TAMPER COMMANDS
"""

"""rXf - forward requests/responses"""
def rXf_function(*args, requests=True, responses=True):
    # TODO rqf to also duplicate and resend - or use rqr?
    """find all rrids to forward"""
    desired_rrs = weber.rrdb.get_desired_rrs(None if len(args)<1 else args[0])
    rrids = desired_rrs.keys()
    """duplicate all not tampered"""
    # TODO

    """for all connection threads with matching rrid:"""
    for t in [t for t in weber.proxy.threads if t.rrid in rrids]:
        """responses first so race condition won't occur"""
        try:
            if responses and t.waiting_for_response_forward:
                t.continue_sending_response()
        except:
            traceback.print_exc()
            pass
        try:
            if requests and t.waiting_for_request_forward:
                t.continue_forwarding()
        except:
            traceback.print_exc()
            pass
    return []

add_command(Command('raf [<rrid>[:<rrid>]]', 
                    'forward tampered requests and responses', 
                    'tamper', 
                    lambda *args: rXf_function(*args)))

add_command(Command('rqf [<rrid>[:<rrid>]]', 
                    'forward tampered requests', 
                    'tamper', 
                    lambda *args: rXf_function(*args, responses=False)))

add_command(Command('rsf [<rrid>[:<rrid>]]', 
                    'forward tampered responses', 
                    'tamper', 
                    lambda *args: rXf_function(*args, requests=False)))

"""rXtN - tamper (N) requests/responses) / stop tampering"""
def rXtN_function(
        *args, 
        stop=False, 
        only1=False, 
        requests=True, 
        responses=True):
    if stop:
        """stop tampering"""
        if requests:
            weber.config['tamper.requests'].value = False
            weber.proxy.tamper_controller.set_tamper_request_count(0)
            log.info('Requests are no longer tampered.')
        if responses:
            weber.config['tamper.responses'].value = False
            weber.proxy.tamper_controller.set_tamper_response_count(0)
            log.info('Responses are no longer tampered.')
    else:
        """set tampering"""
        """get count"""
        count = 0
        if only1:
            count = 1
        elif args:
            try:
                count = int(args[0])
            except:
                log.err('Invalid tamper count.')
                return []
        if count:
            """tamper first N requests/responses"""
            """disable default tampering"""
            if requests:
                weber.config['tamper.requests'].value = False
                weber.proxy.tamper_controller.set_tamper_request_count(count)
                log.info('First %d requests will be TAMPERED.' % count)
            if responses:
                weber.config['tamper.responses'].value = False
                weber.proxy.tamper_controller.set_tamper_response_count(count)
                log.info('First %d responses will be TAMPERED.' % count)
        else:
            """tamper all; set option and threads"""
            """disable tampering by count"""
            if requests:
                weber.config['tamper.requests'].value = True
                weber.proxy.tamper_controller.set_tamper_request_count(0)
                log.info('Requests will be TAMPERED by default.')
            if responses:
                weber.config['tamper.responses'].value = True
                weber.proxy.tamper_controller.set_tamper_response_count(0)
                log.info('Responses will be TAMPERED by default.')
            '''
            """set all active threads"""
            for t in weber.threads:
                if requests:
                    t.can_forward_request = False
                if responses:
                    t.can_forward_response = False
            ''' # not necessary, cause check is done at the right moment
    return []

add_command(Command('rqt [<N>]', 
                    'tamper next N or all requests', 
                    'tamper', 
                    lambda *args: rXtN_function(*args, responses=False)))
    
add_command(Command('rqt1 [<N>]', 
                    'tamper next 1 request', 
                    'tamper', 
                    lambda *args: rXtN_function(*args, 
                                                only1=True, 
                                                responses=False)))
add_command(Command('rqt- [<N>]', 
                    'stop tampering requests', 
                    'tamper', 
                    lambda *args: rXtN_function(*args, 
                                                stop=True,
                                                responses=False)))
add_command(Command('rst [<N>]', 
                    'tamper next N or all responses', 
                    'tamper', 
                    lambda *args: rXtN_function(*args, requests=False)))
    
add_command(Command('rst1 [<N>]', 
                    'tamper next 1 response', 
                    'tamper', 
                    lambda *args: rXtN_function(*args, 
                                                only1=True, 
                                                requests=False)))
add_command(Command('rst- [<N>]', 
                    'stop tampering responses', 
                    'tamper', 
                    lambda *args: rXtN_function(*args, 
                                                stop=True,
                                                requests=False)))
    
"""
SERVER COMMANDS
"""
def s_function(*args):
    return [s.overview() 
            for s in weber.servers
            if s.sid in get_desired_indices(args[0] if args else None, 
                                            1, 
                                            len(weber.servers))]
add_command(Command('s', 'show server overview', 's', s_function))
def sa_function(*args):
    return [str(s)+'\n' 
            for s in weber.servers
            if s.sid in get_desired_indices(args[0] if args else None, 
                                            1, 
                                            len(weber.servers))]
add_command(Command('sa', 'show known servers', 'sa', sa_function))


"""
WRITE COMMANDS
"""
# w
add_command(Command('w', 'write', 'w', lambda *_: []))


# rsdwa 
def rsdwa_function(*args):
    csp = weber.config['crawl.save_path']
    try:
        weber.config['crawl.save_path'].value = args[0]
        log.info('Downloaded data will be saved at %s.' % args[0])
    except:
        weber.config['crawl.save_path'].value = ''
        log.info('Response data will not be autosaved.')
    return []

add_command(Command('rsdwa [<path>]', 
                    'auto-save response content in given location', 
                    'rsdwa', 
                    rsdwa_function))


'''
# wr
add_command(Command('wr', 'write requests/responses into file', 'wr', lambda *_: []))
'''
"""rXw - write content to file"""
def rXw_function(rrid, rr, *args, **kwargs): # write headers/data/both of desired requests/responses/both into file
    data = b''
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
        data += rr.request.bytes(headers=showheaders, data=showdata)
        if showresponse:
            data += b'\n'
    # deal with responses
    if showresponse:
        r = rr.response
        if r is None:
            data.append(b'Response not received yet...')
        else:
            data += r.bytes(headers=showheaders, data=showdata)
    try:
        with open(path, 'wb') as f:
            f.write(data)
    except Exception as e:
        log.err('Cannot write into file \'%s\'.' % (str(path)))
        log.tprint(str(e))
    return []

add_command(Command('raw <file> [<rrid>[:<rrid>]]', 
                    'write requests and responses into file', 
                    'rXw', 
                    lambda *args: foreach_rrs(rXw_function, *args, mask=0xf)))
add_command(Command('rhw <file> [<rrid>[:<rrid>]]', 
                    'write request and response headers into file', 
                    'rXw', 
                    lambda *args: foreach_rrs(rXw_function, *args, mask=0xe)))
add_command(Command('rdw <file> [<rrid>[:<rrid>]]', 
                    'write request and response data into file', 
                    'rXw', 
                    lambda *args: foreach_rrs(rXw_function, *args, mask=0xd)))
add_command(Command('rqw <file> [<rrid>[:<rrid>]]', 
                    'write requests into file', 
                    'rXw', 
                    lambda *args: foreach_rrs(rXw_function, *args, mask=0xb)))
add_command(Command('rqhw <file> [<rrid>[:<rrid>]]', 
                    'write request headers into file', 
                    'rXw', 
                    lambda *args: foreach_rrs(rXw_function, *args, mask=0xa)))
add_command(Command('rqdw <file> [<rrid>[:<rrid>]]', 
                    'write request data into file', 
                    'rXw', 
                    lambda *args: foreach_rrs(rXw_function, *args, mask=0x9)))
add_command(Command('rsw <file> [<rrid>[:<rrid>]]', 
                    'write responses into file', 
                    'rXw', 
                    lambda *args: foreach_rrs(rXw_function, *args, mask=0x7)))
add_command(Command('rshw <file> [<rrid>[:<rrid>]]', 
                    'write response headers into file', 
                    'rXw', 
                    lambda *args: foreach_rrs(rXw_function, *args, mask=0x6)))
add_command(Command('rsdw <file> [<rrid>[:<rrid>]]', 
                    'write response data into file', 
                    'rXw', 
                    lambda *args: foreach_rrs(rXw_function, *args, mask=0x5)))

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

