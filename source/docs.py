#!/usr/bin/env python3
"""
This is the wiki source for Weber.
"""

"""import os, sys, re, traceback, tempfile, subprocess
from source import weber
from source import lib
from source import log
#from source.protocols import protocols
from source.protocols.protocols import *
from source.lib import *
from source.structures import RRDB, Event, URI
import difflib
from source.fd_debug import *
"""

# # # # ## ## ### #### ###### ############################ ##### #### ### ## ## # # # #
doc = {}
doc['help'] = """Welcome! This is Weber Framework, an open-source protocol proxy. With Weber you can see the traffic you are creating, modify it and more!

Currently, Weber will forward to {remote} anything sent to {local}:{port} (plaintext) or {local}:{sslport} (encrypted). Use your browser, client or CLI tool to generate some traffic. You should see some lines popping out in Weber. 
That is realtime traffic overview and it indicates Weber is serving as a proxy. Use `pr` command to show the overview manually.

You may be interested in the content of each request or response. This can be shown with `prq` and `prs` commands, respectively. Depending on the protocol being proxied, you can also print headers (`prh`) or data (`prd`). 

There is a number of options Weber can be configured with. You can use 'weber.conf' file or `o` and `os` commands to view and alter them.

Weber has many features. To list basic commands, their syntax and short description, use '?' symbol. For more specific commands, write part of the command and then append the '?' symbol. For example, writing `prq?` show commands relevant to Printing ReQuests. Not all of them are shown, though, some of them needs longer part of the command to be shown.

To read more about commands, append two '??' symbols.

Sometimes result can be huge. Use '~' symbol to show lines with matching keyword. For example, `prqh~Cookie` will show only request headers which have something to do with Cookie. If you need more complex patterns, use '~~' for regex matching. For example `prsh~~(200 OK|404 Not Found)`.

Append `{modifier}L` to show the result in less. If you want to use different symbol than '{modifier}', consider changing the 'interaction.command_modifier' option.

HAVE FUN.
"""

# analysis
doc['ap'] = """"""
doc['ar'] = """"""

# brute
doc['b'] = """"""
doc['bl'] = """"""

doc['bfi'] = """"""
doc['br'] = """"""
doc['bra'] = """"""
doc['brf'] = """Note: No dictionary is needed.
"""

# compare
doc['c'] = """"""
doc['cr'] = """"""
doc['crX'] = """"""
doc['cru'] = """"""

# event
doc['e'] = """Events are used to group relevant request-response pairs together. Use `e` to print them! 
"""
doc['ea'] = """With `ea` command, request-response pairs are assigned an EID. Multiple request-respons pairs can be used at once. 
"""
doc['ed'] = """With `ea` command, EID is removed from given request-response pairs.
"""
doc['et'] = """Type can be assigned for events using `et` command. This can be useful for orientation among huge amount of traffic. Additionaly, security tests are performed on certain event types:
    login:
        Cookie management (#TODO)
    logout:
        Cookie management (#TODO)
    search:
        Reflected XSS (#TODO)
    email:
        automatic tests are ignored (#TODO)
""" # TODO what is tested for special types?

# modify
doc['m'] = """
"""
doc['mt'] = """
"""
doc['mr'] = """Received requests and responses can be modified using your favourite text editor with `mrq` and `mrs`, respectively. Modifying multiple RRs is not supported (use spoofs instead). 
Favourite editor command can be configured under edit.command option.
"""
doc['mrq'] = """
"""
doc['mrs'] = """
"""

# options
doc['o'] = """Active Weber configuration can be printed with `pwo` and `o` command.

Default configuration is located in source/weber.py.
User configuration can be specified in weber.conf in Weber root directory.
Configuration can be changed on the fly using the `os` command.
"""
doc['os'] = """Active Weber configuration can be changed using the `os` command. User-specific keys can also be defined.
"""

# print
doc['par'] = """
"""
doc['pc'] = """Cookies for specific requests are printed with `pc` command. To see Set-Cookie responses, use `pcs` command.
"""
doc['pcs'] = """Set-Cookie headers can be searched with `pcs` command.
"""
doc['ph'] = """
"""
doc['phc'] = """HTML comments can be searched with `phc` command.
"""
doc['phf'] = """Forms present on given page are shown with `pf` command.
"""
doc['phl'] = """Links from all known tags are printed with `phl` command. To see their context, use `phlc` command.
"""
doc['phlc'] = """Links from all known tags together with their context are printed with `phlc` command.
"""
doc['phm'] = """HTML <main> tags can be searched with `phm` command.
"""
doc['phs'] = """You can do interval search with `phs` command. Note that for certain elements (form, comment, etc.) there are other predefined commands.
"""

doc['pp'] = """Parameters of selected requests are printed with `pp` command.
"""
doc['pr'] = """Use `pr` or `pro` commands to get an overview of all captured request-response pairs, or `pt`, `ptr`, `ptro` for template overview. There are optional parameters 'e', 's', 't', 'u'. You can additionaly specify RRIDs of entries to show, separated by commas and hyphens (e.g. 1,2,4-7).

You can see various columns:
    Time     - Time of request being forwarded to the remote server
             - shown if overview.show_time is set to True or 't' is used as argument
    EID      - Event ID for this request-response pair
             - shown if overview.show_event is set to True or 'e' is used as argument
    RRID     - ID of request-response pair
             - always shown
    Server   - Server the request is sent to (actually URI without the path)
             - shown if overview.show_uri is set to True or 'u' is used as argument
    Request  - Request essential data (method and path for HTTP)
             - always shown
             - path can be ellipsized if overview.short_request is set to True
    Response - Response essential data (status code and status for HTTP)
             - always shown
    Size     - size of response data
             - shown if overview.show_size is set to True or 's' is used as argument

Entries are shown in real-time if overview.realtime is set to True.
Request and responses with [T] prepended are tampered and must be forwarded manually. See `t` for more information.
Entries with emphasized RRID were marked as interesting by analysis processes. Use `pa` to see the reason.

You can use `proa` to see only entries with analysis notes.
You can use `prol` and `ptrol`, respectively, to see only last 10 entries.
You can use `prot` to see only entries with active tampering.
"""

doc['prX'] = """Commands starting with `pr` are used to show request and/or response headers and/or data.
"""

doc['pws'] = """Spoofing feature allows you to alter the requested content on the fly:
- by specifying the file which should be used instead the real response (`sf`)
- by modifying the response with regular expressions (`sr`) 
"""
doc['pwsf'] = """
"""
doc['pwsr'] = """
"""

# quit

# spoofing
doc['sfa'] = """
 (note that the request is sent to remote server to get valid HTML headers.
""" # TODO
doc['sfd'] = """
"""
doc['sra'] = """
    First character is the delimiter.
    Examples:
        sra /http/https/
        sra /\/etc\/hostz/\/etc\/hosts/
        sra |/etc/hostz|/etc/hosts|
""" # TODO
doc['srd'] = """
Unlike `sra`, the parameter is not escaped.
""" # TODO

# tamper
doc['t'] = """
"""
doc['tr'] = """
"""
doc['trf'] = """
"""
doc['trq'] = """
"""
doc['trqa'] = """Toggles tamper.requests value.
"""
doc['trs'] = """
"""
doc['trsa'] = """Toggles tamper.responses value.
"""
doc['trqf'] = """
"""
doc['trsf'] = """
"""

# write
doc['w'] = """
"""
doc['wr'] = """
"""
doc['wrX'] = """
"""



