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
from bs4 import Comment

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
        for k, v in weber.commands.items():
            length = 40
            if k == '': # empty command - just print long description
                continue
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

def foreach_rrs(function, *args, **kwargs):
    """
    This method iterates through desired RRs and runs desired function on them.
    RRs are expected to be the last item of *args.
    """
    result = []
    try:
        desired_rrs = weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1]).items()
    except Exception as e:
        log.err('Cannot get desired rrs: %s' %  (str(e)))
        log.err('See traceback:')
        traceback.print_exc()
        desired_rrs = []
    for rrid, rr in weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1]).items():
    #for rrid, rr in weber.rrdb.get_desired_rrs(args).items():
        tmpresult = []
        tmpresult.append('{grepignore}%s-- #%d --%s' % (log.COLOR_BLUE+log.COLOR_BOLD, rrid, log.COLOR_NONE))
        tmpresult += function(rrid, rr, *args[:-1], **kwargs)
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
    tmpresult = []
    #for tagname, attr_key, attr_value in tags:
    #    for t in rr.response.find_tags(tagname, attr_key=attr_key, attr_value=attr_value, form=('value' if valueonly else 'xml')):
    #        tmpresult.append(t)
    #return tmpresult
    result = []
    if attrs is None:
        for startbytes, endbytes in startends:
            result += [x[1].decode() for x in find_between(rr.response.data, startbytes, endbytes, inner=valueonly)]
    else:
        for (startbytes, endbytes), attr in zip(startends, attrs):
            result += [x[1].decode() for x in rr.response.find_html_attr(startbytes, endbytes, attr)]
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
    print(weber.rrdb.rrs[1].response.find_tags('form'))
    return []
add_command(Command('test', 'prints test message', '', test_function))














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
    for rrid, rr in weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1]).items():
        rr.eid = eid
        weber.events[eid].rrids.add(rrid)
    return []
ea_description="""With `ea` command, request-response pairs are assigned an EID. Multiple request-respons pairs can be used at once. 
"""
add_command(Command('ea eid <rrid>[:<rrid>]', 'adds requests/responses into event', ea_description, ea_function))

def ed_function(*args):
    for rrid, rr in weber.rrdb.get_desired_rrs(None if len(args)<1 else args[-1]).items():
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
m_description=''
add_command(Command('m', 'modify', m_description, lambda *_: []))
mr_description="""Received requests and responses can be modified using your favourite text editor with `mrq` and `mrs`, respectively. Modifying multiple RRs is not supported (use spoofs instead). 
Favourite editor command can be configured under edit.command option.
"""
add_command(Command('mr', 'modify request/response', mr_description, lambda *_: []))
mrq_description="""
"""
mrs_description="""
"""
def mr_function(*args):
    try:
        rrid = int(args[1])
        if args[0] == 'request': 
            r = weber.rrdb.rrs[rrid].request
        elif args[0] == 'response':
            r = weber.rrdb.rrs[rrid].response
        else:
            log.err('Invalid type.')
            return []
        if r is None:
            log.err('Non-existent %s for RRID #%d.' % (args[0], rrid))
            return []
    except:
        log.err('Invalid RRID.')
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
        if args[0] == 'request': 
            weber.rrdb.rrs[rrid].request = Request(f.read(), r.should_tamper, r.forward_stopper)
        elif args[0] == 'response':
            weber.rrdb.rrs[rrid].response = Response(f.read(), r.should_tamper, r.forward_stopper)
    # restore debug and realtime overview settings
    for k, v in oldconfig.items():
        weber.config[k] = v
    return []
        
add_command(Command('mrq <rrid>', 'modify request', mrq_description, lambda *args: mr_function('request', *args)))
add_command(Command('mrs <rrid>', 'modify response', mrs_description, lambda *args: mr_function('response', *args)))












"""
OPTIONS COMMANDS
"""
o_function = lambda *_: ['    %-20s  %s' % (k, (v[0] if v[1] != str else '\''+v[0]+'\'')) for k,v       in weber.config.items()]
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

# pc
def pc_function(_, rr, *__):
    try:
        cookies = rr.request.headers[b'Cookie'].split(b';')
        cookies = dict([tuple(c.split(b'=')) for c in cookies])
        maxlen = max([0]+[len(k.decode().strip()) for k in cookies.keys()])
        return ['%*s: %s' % (maxlen, k.decode(), v.decode()) for k,v in cookies.items()]
    except:
        return []
pc_description = """Cookies for specific requests are printed with `pc` command. To see Set-Cookie responses, use `pcs` command.
"""
add_command(Command('pc [<rrid>[:<rrid>]]', 'print cookies', pc_description, lambda *args: foreach_rrs(pc_function, *args)))
# pcs
def pcs_function(_, rr, *__):
    try:
        cookie = rr.response.headers[b'Set-Cookie']
        print(cookie)
        # TODO parse cookie parameters
        return []
    except:
        return []
pcs_description = """Set-Cookie headers can be searched with `pcs` command.
"""
add_command(Command('pcs [<rrid>[:<rrid>]]', 'print Set-Cookie occurences', pcs_description, lambda *args: foreach_rrs(pcs_function, *args))) #TODO
add_command(Command('pe [<eid>[:<eid>]]', 'print events', e_description, e_function))

# pf
pf_description = """Forms present on given page are shown with `pf` command.
"""
#add_command(Command('pf [<rrid>[:<rrid>]]', 'print forms', pf_description, lambda *args: foreach_rrs(find_tags, *args, tags=[('form', None, None)], valueonly=False)))
add_command(Command('pf [<rrid>[:<rrid>]]', 'print forms', pf_description, lambda *args: foreach_rrs(find_tags, *args, startends=[(b'<form', b'</form>')], valueonly=False)))

# pl
pl_description = """Links from all known tags are printed with `pl` command. To see their context, use `plc` command.
"""
add_command(Command('pl [<rrid>[:<rrid>]]', 'print links', pl_description, lambda *args: foreach_rrs(find_tags, *args, startends=[x[:2] for x in Response.link_tags], attrs=[x[2] for x in Response.link_tags], valueonly=True)))
plc_description = """Links from all known tags together with their context are printed with `plc` command.
"""
add_command(Command('plc [<rrid>[:<rrid>]]', 'print links with context', plc_description, lambda *args: foreach_rrs(find_tags, *args, startends=[x[:2] for x in Response.link_tags], valueonly=False)))

# pn
pn_description = """HTML comments can be searched with `pn` command.
"""
#add_command(Command('pn [<rrid>[:<rrid>]]', 'print comments', pn_description, lambda *args: foreach_rrs(find_tags, *args, tags=[('comment', None, None)], valueonly=True)))
add_command(Command('pn [<rrid>[:<rrid>]]', 'print comments', pn_description, lambda *args: foreach_rrs(find_tags, *args, startends=[(b'<!--', b'-->')], valueonly=False)))

# pp
def pp_function(_, rr, *__):
    maxlen = max([0]+[len(k) for k in rr.request.parameters.keys()])
    return ['%*s: %s' % (maxlen, k.decode(), '' if v is None else v.decode()) for k, v in rr.request.parameters.items()]
pp_description = """Parameters of selected requests are printed with `pp` command.
"""
add_command(Command('pp [<rrid>[:<rrid>]]', 'print parameters', pp_description, lambda *args: foreach_rrs(pp_function, *args)))

# pr_function defined in structures.py because it is also used by proxy (realtime overview)
pr_description = """Use `pr` command to get an overview of all captured request-response pairs. Size of the response and time can be optionally showed as well (using overview.size and overview.time configuration parameters) {#TODO}.
"""
add_command(Command('pr [<rrid>[:<rrid>]]', 'print request-response overview (alias for `pro`)', pr_description, lambda *args: weber.rrdb.overview(args, showlast=False, onlytampered=False)))
add_command(Command('pro [<rrid>[:<rrid>]]', 'print request-response pairs', pr_description, lambda *args: weber.rrdb.overview(args, showlast=False, onlytampered=False)))

# prol
prol_description="""
"""
add_command(Command('prol [<rrid>[:<rrid>]]', 'print last request-response overview', prol_description, lambda *args: weber.rrdb.overview(args, showlast=True, onlytampered=False)))
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
        result += rr.request.lines(headers=showheaders, data=showdata)
        if showresponse:
            result.append('')
    # deal with responses
    if showresponse:
        if rr.response is None:
            result += 'Response not received yet...'
        else:
            result += rr.response.lines(headers=showheaders, data=showdata)
    return result
prX_description="""Commands starting with `pr` are used to show request and/or response headers and/or data.
"""
add_command(Command('pra [<rrid>[:<rrid>]]', 'print requests and responses verbose', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0xf)))
add_command(Command('prh [<rrid>[:<rrid>]]', 'print request and response headers', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0xe)))
add_command(Command('prd [<rrid>[:<rrid>]]', 'print request and response data', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0xd)))
add_command(Command('prq [<rrid>[:<rrid>]]', 'print requests verbose', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0xb)))
add_command(Command('prqh [<rrid>[:<rrid>]]', 'print request headers', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0xa)))
add_command(Command('prqd [<rrid>[:<rrid>]]', 'print request data', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0x9)))
add_command(Command('prs [<rrid>[:<rrid>]]', 'print responses verbose', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0x7)))
add_command(Command('prsh [<rrid>[:<rrid>]]', 'print response headers', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0x6)))
add_command(Command('prsd [<rrid>[:<rrid>]]', 'print response data', prX_description, lambda *args: foreach_rrs(prx_function, *args, mask=0x5)))


# pw 
add_command(Command('pw', 'print weber-related information', '', lambda *_: []))

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
add_command(Command('pwt', 'print alive threads', '', lambda *_: ['    %s:%d%s' % (t.host.decode(), t.port, t.path) if t.port != 0 else '    ?' for t in weber.proxy.threads]))

"""
Quit
"""
add_command(Command('q', 'quit', '', lambda *_: [])) # solved in weber



"""
Spoofing
"""
# s
add_command(Command('s', 'print spoof settings (alias for pws)', pws_description, pws_function))

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
# TODO trq, trs, trq <n>, trs <n>

# trf
def trf_function(_, rr, *__):
    # responses first so race condition won't occur
    try:
        rr.response.forward()
    except:
        pass
    try:
        rr.request.forward()
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
    log.info('Responses will be %s by default.' % ('TAMPERED' if trs else 'FORWARDED'))
    return []
add_command(Command('trsa', 'toggle default response tamper behavior', trsa_description, trsa_function))

# trqf
def trqf_function(_, rr, *__):
    try:
        rr.request.forward()
    except:
        log.err('No request is available.')
    return []
trqf_description = """
"""
add_command(Command('trqf [<rrid>[:<rrid>]]', 'forward tampered request', trqf_description, lambda *args: foreach_rrs(trqf_function, *args)))

# trsf
def trsf_function(_, rr, *__):
    try:
        rr.response.forward()
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
def wrx_function(_, rr, *args, **kwargs): # write headers/data/both of desired requests/responses/both into file
    # this function just appends! 
    data = []
    try:
        path = args[0]
    except:
        log.err('Path to file not specified or incorrect RR interval.')
        return []
    showrequest = bool(kwargs['mask'] & 0x8)
    showresponse = bool(kwargs['mask'] & 0x4)
    showheaders = bool(kwargs['mask'] & 0x2)
    showdata = bool(kwargs['mask'] & 0x1)
    # deal with requests
    if showrequest:
        data += rr.request.lines(headers=showheaders, data=showdata, as_string=False)
        if showresponse:
            data.append(b'')
    # deal with responses
    if showresponse:
        data += rr.response.lines(headers=showheaders, data=showdata, as_string=False)
    try:
        with open(path, 'ab') as f:
            for line in data:
                f.write(line)
                f.write(b'\n')
    except Exception as e:
        log.err('Cannot write into file \'%s\'.' % (str(path)))
        print(e)
    return []

def wrx_eraser(mask, *args):
    # first erase the file
    try:
        with open(args[0], 'wb') as f:
            pass
    except:
        log.err('Cannot open file for writing.')
        return []
    # now write each desired rr
    return foreach_rrs(wrx_function, *args, mask=mask)
wrX_description="""
"""
add_command(Command('wra <file> [<rrid>[:<rrid>]]', 'write requests and responses', wrX_description, lambda *args: wrx_eraser(0xf, *args)))
add_command(Command('wrh <file> [<rrid>[:<rrid>]]', 'write request and response headers', wrX_description, lambda *args: wrx_eraser(0xe, *args)))
add_command(Command('wrd <file> [<rrid>[:<rrid>]]', 'write request and response data', wrX_description, lambda *args: wrx_eraser(0xd, *args)))
add_command(Command('wrq <file> [<rrid>[:<rrid>]]', 'write requests verbose', wrX_description, lambda *args: wrx_eraser(0xb, *args)))
add_command(Command('wrqh <file> [<rrid>[:<rrid>]]', 'write request headers', wrX_description, lambda *args: wrx_eraser(0xa, *args)))
add_command(Command('wrqd <file> [<rrid>[:<rrid>]]', 'write request data', wrX_description, lambda *args: wrx_eraser(0x9, *args)))
add_command(Command('wrs <file> [<rrid>[:<rrid>]]', 'write responses verbose', wrX_description, lambda *args: wrx_eraser(0x7, *args)))
add_command(Command('wrsh <file> [<rrid>[:<rrid>]]', 'write response headers', wrX_description, lambda *args: wrx_eraser(0x6, *args)))
add_command(Command('wrsd <file> [<rrid>[:<rrid>]]', 'write response data', wrX_description, lambda *args: wrx_eraser(0x5, *args)))



