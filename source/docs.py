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
doc['help'] = (
    """Welcome! This is Weber Framework, an open-source protocol proxy.
With Weber you can see the traffic, modify it and more!

Currently, Weber will forward anything sent to '{local}:{port}' but
allows you to see the content and maniuplate it. Use your browser,
client or CLI tool to generate some traffic. You should see some 
lines popping out in Weber. 
That is realtime traffic overview and it indicates Weber is serving 
as a proxy. Use `pr` command to show the overview manually.

You may be interested in the content of each request or response. This
can be shown with `prq` and `prs` commands, respectively. Depending
on the protocol being proxied, you can also print headers (`prh`) 
or data (`prd`). 

There is a number of options Weber can be configured with. You can use 
'weber.conf' file or `o` and `os` commands to view and alter them.

Weber has many features. To list basic commands, their syntax and short
description, use '?' symbol. For more specific commands, write part 
of the command and then append the '?' symbol. For example, writing 
`prq?` show commands relevant to Printing ReQuests. Not all of them are 
shown, though, some of them needs longer part of the command to show.

To read more about commands, append two '??' symbols.

Sometimes result can be huge. Use '~' symbol to show lines with 
matching keyword. For example, `prqh~Cookie` will show only request 
headers which have something to do with Cookie. If you need more 
complex patterns, use '~~' for regex matching. For example 
`prsh~~(200 OK|404 Not Found)`.

Append `{modifier}L` to show the result in less. If you want to use
different symbol than '{modifier}', consider changing the 
'interaction.command_modifier' option.

HAVE FUN.
""") # TODO fix commands

# analysis
doc['a'] = (
    """Weber supports automatic testing of common security weaknesses. 
Enabled tests can be printed with `ap` command.

Currently, request-response tests are supported. If a problem is 
detected for a RR pair, its ID is emphasized in RR overview (shown with
`ro` command). Detailed test results are shown with `ar` command. 
The RR analysis is automatically performed after the response is 
received if 'analysis.immediate' option is set. You can run analysis 
manually with `arr` command as well.
""")

doc['ap'] = (
    """Use `ap` command to show what analysis packages are enabled and what
tests will be performed.""")
doc['ar'] = """The `ar` command print analysis result for individual RR
pairs. See the documentation for `a` command for more information.
"""
doc['arr'] = """The `arr` command runs analysis on chosen RR pairs. 
If a security weakness is found, the user is informed."""

# brute
doc['b'] = (
    """Commands starting with 'b' are designed to send automatically 
modified RRs to the remote server. This allows:
- bruteforcing,
- fault injection testing (in development).

Use `b` command to show currently loaded dictionary. Dictionary is 
loaded with `bl` command.
""")
doc['bl'] = (
    """The `bl` command imports specified file as bruteforce dictionary. 
The following format is expected:

index{separator}htm{separator}...
index{separator}php{separator}...
...

The set (line) may contain arbitrary number of values. Separator is 
specified in 'brute.value_separator' option. Alternatively, 
'brute.set_separator' option can specify different set separator than 
a newline character. Arbitrary number of sets can be specified.

It is recommended to use `b` command after loading a dictionary to see 
whether the dictionary has been loaded properly.
""")

doc['bfi'] = """""" # TODO
doc['br'] = (
    """After a dictionary is loaded with `bl` command, you can use `bra`
command to use it for brutefoce test. 
Placeholders {placeholder}n{placeholder} in chosen template RRs are 
replaced with set values on the fly and forwarded to the remote server. 
The 'n' specifies index of the value.

Placeholder is specified in 'brute.placeholder' option.

Throttling is adjusted with brute.rps option. It is maximum number of
requests per second.
""")



# compare
doc['compare_rr'] = (
    """Requests and responses can be compared. Such commands ends with
'c', 'c1', 'c2', 'cc', or 'cd' (see the differences below).

The syntax is <command> <rrid1> <rrid2>.
If using 'c' command form, all lines from both subjects are shown. 
Different lines are denoted by + and - signs.

Other command forms are:
  'c1' - show lines unique for first RR,
  'c2' - show lines unique for second RR,
  'cc' - show only lines present in both RRs,
  'cd' - show only lines that differ with + and - signs
""")

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
doc['m'] = """Commands starting with 'm' serve for data modification. 

Currently, requests and responses can be modified. Check documentation on `mr` command for detailed information.
"""
doc['mr'] = """Received requests and responses can be modified using your favourite text editor with `mrq` and `mrs`, respectively. Template counterparts are modified with `mtrq` and `mtrs` commands, respectively. This is useful when data waiting to transmit must be modified or when preparing new requests for sending from Weber without endpoint client. If you want to force template creation even when tampering or without data change, use `mrq!` or `mrs!` commands, respectively.

Favourite editor command can be configured under edit.command option.

Modifying multiple RRs at once is not supported (use spoofs instead). 

WARNING: If appending a header to requests/responses with empty data part, make sure the new header is added BEFORE the \\x0d\\x0a separator! The best way to insert a new header is to go to the end of previous header, press Enter and specify new header. You can use hexdump to check your changes with `prqx`, `prsx`, `ptrqx` and `ptrsx` commands.
"""

# options
# TODO to weber section
# TODO user-specific keys usage
doc['wo'] = (
    """Active Weber configuration can be printed with `wo` command.
User-specific keys can also be defined. For those, at sign (@) will
be automatically prepended.

Default configuration is located in 'source/weber.py' file.
User configuration can be specified in 'weber.conf' file in the Weber 
root directory.
Configuration can be changed on the fly using the `wos` command.
""")

# print
#doc['p'] = """Commands starting with `p` can be used to print various information. Use documentation for each command.
#"""
doc['rc'] = (
    """Cookies for specific requests are printed with `rc` command. 
To see Set-Cookie responses, use `rcs` command.
""")
doc['rcs'] = """Set-Cookie headers can be searched with `rcs` command.
"""
doc['rH'] = (
"""Commands starting with 'rH' serve for extracting HTML-related 
information from the communication.
""")
doc['rHc'] = """HTML comments can be searched with `rHc` command.
"""
doc['rHf'] = (
    """Forms present on given page are shown with `rHf` command.
""")
doc['rHl'] = (
    """Links from all known tags are printed with `rHl` command. 
To see their context as well, use `rHlc` command.
""")
doc['rHlc'] = (
    """Links from all known tags together with their context are 
    printed with `rHlc` command.
""")
doc['rHm'] = """HTML <main> tags can be searched with `rHm` command.
"""
doc['rHs'] = (
    """You can do interval search with `rHs` command. Note that 
for certain elements (form, comment, etc.) there are other 
predefined commands.
""")

doc['rp'] = (
"""Parameters of selected requests are printed with `rp` command.
""")
doc['r'] = (
    """Use `r` or `ro` commands to get an overview of all captured 
request-response pairs. 
There are optional parameters 'e', 's', 't', 'u'. 
You can additionaly specify RRIDs of entries to show, separated by 
commas and hyphens (e.g. 1,2,4-7).

You can see various columns:
    Time     = Time of request being forwarded to the remote server
             - shown if overview.show_time is set to True or 't' 
               is used as argument
    EID      = Event ID for this request-response pair
             - shown if overview.show_event is set to True or 'e' 
               is used as argument
    RRID     = ID of request-response pair
             - always shown
    Server   = URI of the server the request is sent to
             - shown if overview.show_uri is set to True or 'u' 
               is used as argument
    Request  = Request essential data (method and path for HTTP)
             - always shown
             - path can be ellipsized if overview.short_request is set
    Response = Response essential data (status code and status for HTTP)
             - always shown
    Size     = size of response data
             - shown if overview.show_size is set to True or 's' is 
               used as argument

Entries are shown in real-time if integration.realtime_overview is set.
Request and responses with [T] prepended are tampered and must be 
forwarded manually. See `rqt` or `rst` for more information.

Entries with emphasized RRID were marked as interesting by analysis 
processes. Use `ar` to see the reason.

You can use `roa` to see only entries with analysis notes.
You can use `rol` to see only last 10 entries.
You can use `rot` to see only entries with active tampering.
""")

doc['rX'] = (
    """Commands `ra`, `rh`, `rd`, `rq`, `rqh`, `rqd`, `rs`, `rsh`, `rsd`
are used to show request and/or response headers and/or data in detail. 
Use `ra` to print everything.

If the commands end with 'x', the result is printed as hexdump. 
This is usefull for checking for special characters.
""")

# TODO move to weber part
doc['w'] = """Commands starting with `w` are designed to show and set
Weber-related info. Sometimes, they have shorter aliases with regards 
to the functionality.
"""

'''
doc['pwm'] = """The `pwm` command shows local -> remote URI mapping. The translation is done tranparently by Weber.
"""
'''

doc['wt'] = (
"""For debugging purposes, you can show alive Weber threads 
with `wt` command.
""")

doc['ws'] = (
"""Spoofing feature allows you to alter the requested content 
on the fly:
- by specifying the file which should be used instead the real 
  response (`rssf`),
- by modifying the request with regular expressions (`rqs`),
- by modifying the response with regular expressions (`rss`).

Use `ws` command to show current spoofing settings.
""")

doc['rssf'] = (
    """If file spoofing has been configured with `rssfa` command, you can
print the mapping with `rssf` command.

Use `rssfa` and `rssfD` commands to configure/delete file spoofing.
""")
doc['rXs'] = (
    """Use `rqsa`, `rqsD`, `rssa` and `rssD` commands to configure
regular expression spoofing. Use `rqs` and `rss` commands to see the
actual configuration.
""")

# quit
doc['q'] = """Quit. What do you expect?"""

# spoofing
doc['sf'] = (
    """File can be spoofed with `rssfa` command. After that, when Weber
detects a request for that file, it quietly replaces the content with 
local file of your choosing. This is especially useful when you are 
testing a page and you need a modified version of Javascript code to 
see crucial control information.

Example: 
   rssfa https://www.cia.gov/++theme++contextual.agencytheme/images/logo.png /tmp/anonymous.png

Note: The request is sent to remote server anyway to get valid 
      HTML headers.

The `rssfD` command is used to delete a file spoofing entry.
""")

doc['sr'] = (
    """Commands starting with `rqs` or `rss` are used to define regular 
expressions which are used on received requests or responses. For 
adding a new rule, use `rqsa` (requests) or `rssa` (responses) command. 
To delete a rule, use `rqsD` (requests) or `rssD` (responses) command.
""")

doc['rXsa'] = (
"""The `srqa` and `srsa` commands are used to define regular expressions
which are used on received requests or responses, respectively. 
The first character is the delimiter.

    Examples:
        srsa /http/https/
        srsa /\/etc\/hostz/\/etc\/hosts/
        srsa |/etc/hostz|/etc/hosts|
""")
doc['rXsD'] = (
    """The `rqsD` and `rssD` commands are used to remove a regex spoofing
entry. Unlike `rqsa` and `rssa`, the parameter is not escaped.
""") 

# tamper
doc['tamper'] = (
    """One of the most essential features of a proxy is to pause the 
transmission of data between the client and the server. Those data can
be reviewed and/or modified before actual transmission.

Default behaviour is to forward everything immediately. This can be 
toggled by setting tamper.requests and tamper.responses options, or, 
more conveniently, using `rqt` and `rst` commands. Number of 
requests/responses to tamper can be specified, by default all 
requests/responses are to be tampered. 
If `rqt1` and `rst1` commands are used instead, only first 
request/response is tampered.

Forward tampered requests and responses with `rf` (both requests and
responses), `rqf` (only requests) or `rsf` (only responses) commands.
Specific requests/responses to be forwarded can be specified.

To stop tampering, use `rqt-` or `rst-` command.

If forwarding request already having a response, the request is
duplicated and forwarded again.

For data modification, check `rqm` and `rsm` commands. For bulk data 
modification with regular expression, check `rqs` and `rss` commands.
""")


# write
doc['w'] = """Commands starting with `w` are designed to write gathered information into files. 

Currently, request and response writing is supported. See documentation for `wr` command for more information.
"""
doc['rsdwa'] = (
"""Use `rsdwa` command to specify path where received files will be 
stored in tree structure while browsing or crawling. Alternatively, 
you can set the path in \'crawl.save_path\' option.

Leaving the path empty means data storing is not desired.
""")

doc['rXw'] = (
    """You can commands ending with 'w' to store gathered requests and/or
responses. This is useful for manual web crawling or when a file is to 
be modified and spoofed later with `rssf` command.

If multiple RR ids are specified, The '_<rrid>' string is appended to 
the given filename to distinct between them.

To manually store exact (decoded) response data, use `rsdw` command. 
For automatic saving consider using `rsdwa` command.
""")

doc['ww'] = """If you need to store your Weber session for later use, take advantage of the`ww` command. This dumps essential Weber structures into a file in binary format. The dump can be later restored with --restore argument.

Example: ./weber --restore dump.web
"""

