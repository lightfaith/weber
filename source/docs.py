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

Currently, Weber will forward to '{remote}' anything sent to '{local}:{port}' (plaintext) or '{local}:{sslport}' (encrypted). Use your browser, client or CLI tool to generate some traffic. You should see some lines popping out in Weber. 
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
doc['a'] = """Weber supports automatic testing of common security weaknesses. Enabled tests can be printed with `ap` command.

Currently, request-response tests are supported. If a problem is detected for a RR pair, its ID is emphasized in RR overview (shown with `pro` command). Detailed test results are shown with `par` command. The RR analysis is automatically performed after the response is received if analysis.immediate option is set. You can run analysis manually with `ar` command as well.
"""

doc['ap'] = """Use `ap` command to show what analysis packages are enabled and what tests will be performed."""
doc['ar'] = """The `ar` command runs analysis on chosen RR pairs. If a security weakness is found, the user is informed."""

# brute
doc['b'] = """Commands starting with 'b' are designed to send template RRs to the remote server. This allows:
- manual resending,
- bruteforcing.

Use `b` or `pwb` command to show currently loaded dictionary. Dictionary is loaded with `bl` command.
"""
doc['bl'] = """The `bl` command imports specified file as bruteforce dictionary. The following format is expected:

index{separator}htm{separator}...
index{separator}php{separator}...
...

The set (line) may contain arbitrary number of values. Separator is specified in brute.value_separator option. Alternatively, brute.set_separator option can specify different set separator than a newline character. Arbitrary number of sets can be specified.

It is recommended to use `b` or `pwb` command after loading a dictionary to see whether the dictionary has been loaded properly.
"""

doc['bfi'] = """""" # TODO
doc['br'] = """After a dictionary is loaded with `bl` command, you can use `bra` command to use it for brutefoce test. Placeholders {placeholder}n{placeholder} in chosen template RRs are replaced with set values on the fly and forwarded to the remote server. The 'n' specifies index of the value.

Placeholder is specified in brute.placeholder option.

Throttling is adjusted with brute.rps option. It is maximum number of requests per second.
"""
doc['brf'] = """Template requests can be forwarded once with `brf` commands. Unlike other `br` commands, no placeholders are modified, and therefore no dictionary loading is required.
"""

# compare
doc['c'] = """Commands starting with 'c' serve for data comparison. Currently, requests or responses (or their parts) can be compared, see documentation for `cr` for more information."""
doc['crX'] = """Commands starting with `cr` serve for request and response comparison. 

The syntax is usually <command> <modifier> <rrid1> <rrid2>.
The <modifier> is one of (1, 2, c, d, D) symbols. This determines the diff format:
- 1 - show lines unique for first RR,
- 2 - show lines unique for second RR,
- c - show lines present in both RRs,
- d - show lines that differ (+ and - signs are prepended to show what lines are added and removed, respectively),
- D - show all lines, mark different lines with + and - signs (like c and d modifiers together).
"""
doc['cru'] = """The `cru` command shows lines that are changed by Weber when links are translated. This is for debug purposes."""

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
doc['mr'] = """Received requests and responses can be modified using your favourite text editor with `mrq` and `mrs`, respectively. Template counterparts are modified with `mtrq` and `mtrs` commands, respectively. This is useful when data waiting to transmit must be modified or when preparing new requests for sending from Weber without endpoint client.

Favourite editor command can be configured under edit.command option.

Modifying multiple RRs at once is not supported (use spoofs instead). 

WARNING: If appending a header to requests/responses with empty data part, make sure the new header is added BEFORE the \\x0d\\x0a separator! The best way to insert a new header is to go to the end of previous header, press Enter and specify new header. You can use hexdump to check your changes with `prqx`, `prsx`, `ptrqx` and `ptrsx` commands.
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
doc['p'] = """Commands starting with `p` can be used to print various information. Use documentation for each command.
"""
doc['par'] = """The `par` command print analysis result for individual RR pairs. See the documentation for `a` command for more information.
""" # TODO
doc['pc'] = """Cookies for specific requests are printed with `pc` command. To see Set-Cookie responses, use `pcs` command.
"""
doc['pcs'] = """Set-Cookie headers can be searched with `pcs` command.
"""
doc['ph'] = """Commands starting with 'ph' serve for extracting HTML-related information from the communication.
"""
doc['phc'] = """HTML comments can be searched with `phc` command.
"""
doc['phf'] = """Forms present on given page are shown with `pf` command.
"""
doc['phl'] = """Links from all known tags are printed with `phl` command. To see their context as well, use `phlc` command.
"""
doc['phlc'] = """Links from all known tags together with their context are printed with `phlc` command.
"""
doc['phm'] = """HTML <main> tags can be searched with `phm` command.
"""
doc['phs'] = """You can do interval search with `phs` command. Note that for certain elements (form, comment, etc.) there are other predefined commands.
"""

doc['pp'] = """Parameters of selected requests are printed with `pp` command.
"""
doc['pr'] = """Use `pr` or `pro` commands to get an overview of all captured request-response pairs, or `pt`, `ptr`, `ptro`, respectively, for template overview. There are optional parameters 'e', 's', 't', 'u'. You can additionaly specify RRIDs of entries to show, separated by commas and hyphens (e.g. 1,2,4-7).

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
Entries with emphasized RRID were marked as interesting by analysis processes. Use `par` to see the reason.

You can use `proa` to see only entries with analysis notes.
You can use `prol` and `ptrol`, respectively, to see only last 10 entries.
You can use `prot` to see only entries with active tampering.
"""

doc['prX'] = """Commands starting with `pr` are used to show request and/or response headers and/or data in more detail. Use `pra` to print everything.

If the commands ends with an 'x', the result is printed as hexdump. This is usefull for checking for special characters.
"""

doc['pw'] = """Commands starting with `pw` are designed to show Weber-related info. Sometimes, they have shorter aliases with regards to the functionality (e.g. `pwo` -> `o`).

"""

doc['pwm'] = """The `pwm` command shows local -> remote URI mapping. The translation is done tranparently by Weber.
"""
doc['pwt'] = """For debugging purposes, you can show alive Weber threads with `pwt` command.
"""

doc['pws'] = """Spoofing feature allows you to alter the requested content on the fly:
- by specifying the file which should be used instead the real response (`sf`),
- by modifying the response with regular expressions (`sr`).

Use `s` or `pws` command to show current spoofing settings.
"""

doc['pwsf'] = """If file spoofing has been configured with `sfa` command, you can print the mapping with `pwsf` command.
"""
doc['pwsr'] = """If regex spoofing has been configured with `srqa` or `srsa` command, you can print the mapping with `pwsr`, `pwsrq` or `pwsrs` commands, or their aliases (`sr`, `srq`, `srs`, respectively).
"""

# quit
doc['q'] = """Quit. What do you expect?"""

# spoofing
doc['sf'] = """File can be spoofed with `sfa` command. After that, when Weber detects a request for that file, it quietly replaces the content with local file of your choosing. This is especially useful when you are testing a page and you need a modified version of Javascript code to see crucial control information.

Example: 
   sfa https://www.cia.gov/++theme++contextual.agencytheme/images/logo.png /tmp/anonymous.png

Note: The request is sent to remote server anyway to get valid HTML headers.

The `sfd` command is used to delete a file spoofing entry.
"""

doc['sr'] = """ Commands starting with `sr` are used to define regular expressions which are used on received requests or responses. For adding a new rule, use `srqa` (requests) or `srsa` (responses) command. To delete a rule, use `srqd` (requests) or `srsd` (responses) command.

"""
doc['srXa'] = """The `srqa` and `srsa` commands are used to define regular expressions which are used on received requests or responses, respectively. The first character is the delimiter.
    Examples:
        srsa /http/https/
        srsa /\/etc\/hostz/\/etc\/hosts/
        srsa |/etc/hostz|/etc/hosts|
"""
doc['srXd'] = """ The `srqd` and `srsd` commands are used to remove a regex spoofing entry. Unlike `srqa` and `srsa`, the parameter is not escaped.
""" 

# tamper
doc['t'] = """One of the most essential features of a proxy is to pause the transmission of data between the client and the server. Those data can be reviewed and/or modified before actual transmission.

Default behaviour is to forward everything immediately. This can be toggled by setting tamper.requests and tamper.responses options, or, more conveniently, using `trqa` and `trsa` commands. If `trq` and `trs` commands are used instead, only first N requests/responses (default = 1) are tampered.

Forward tampered requests and responses with `trqf`, `trsf` or `trf` commands.

For data modification, check `m` commands. For bulk data modification with regular expression, check `sr` commands.
"""

doc['trf'] = """Use `trf` command to forward all tampered requests and responses.
"""
doc['trq'] = """Use `trq` command to tamper next N requests. Default value is 1.
"""
doc['trqa'] = """Toggle tamper.requests value with the `trqa` command.
"""
doc['trs'] = """Use `trs` command to tamper next N responses. Default value is 1.
"""
doc['trsa'] = """Toggle tamper.responses value with the `trsa` command.
"""
doc['trqf'] = """Use `trqf` command to forward all tampered requests. Tampered responses are not forwarded.
"""
doc['trsf'] = """Use `trsf` command to forward all tampered responses. Tampered requests are not forwarded.
"""

# write
doc['w'] = """Commands starting with `w` are designed to write gathered information into files. 

Currently, request and response writing is supported. See documentation for `wr` command for more information.
"""
doc['wr'] = """You can use `wr` commands to store gathered requests and/or responses. This is useful for web crawling or when a file is to be modified and spoofed later with `sfa` command.

If multiple RR ids are specified, The '_<rrid>' string is appended to the given filename to distinct between them.

To store exact response data, use `wrsd` command.
"""

doc['ww'] = """If you need to store your Weber session for later use, take advantage of the`ww` command. This dumps essential Weber structures into a file in binary format. The dump can be later restored with --restore argument.

Example: ./weber --restore dump.web
"""

