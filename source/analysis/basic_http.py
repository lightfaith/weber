#!/usr/bin/env python3
"""
Basic analysis for HTTP
"""
import socket, traceback, errno, ssl, re, itertools, threading
from threading import Thread
from collections import OrderedDict
from select import select

from source import weber
from source.lib import *

basic_http = {
    # ----------------
    # options
    'enabled': True,

    # ----------------
    # Inter-RR tests
    #     ('apropos', 
    #      [list of supported protocols (SSL variants excluded)], 
    #      lambda req,res,uri:(('Category', 'Message') or None)
    #     )
    'rr_tests': [

        ('Missing Content-Type', ['http'], lambda _,res,__:(('WARNING', 'Content-Type is not defined.') if res and not res.headers.get(b'Content-Type') else None)),

        ('PHP returned', ['http'], lambda _,res,__:(('SECURITY', 'PHP code returned from server.') if res and is_content_type_text(res.headers.get(b'Content-Type')) and (res.find_tags(startends=[(b'<?php', b'?>')], valueonly=False) or res.find_tags(startends=[(b'<? ', b'?>')], valueonly=False)) else None)),
        ('Cookie without \'HttpOnly\' attribute', ['http'], lambda _,res,__:(('SECURITY', 'Cookie does not have \'HttpOnly\' attribute.') if res and res.headers.get(b'Set-Cookie') and b'httponly' not in [attr.strip().lower() for attr in res.headers[b'Set-Cookie'].split(b';')] else None)), 
        ('Cookie without \'secure\' attribute', ['http'], lambda _,res,uri:(('SECURITY', 'Cookie set over SSL but without \'secure\' attribute.') if res and res.headers.get(b'Set-Cookie') and uri.scheme in ('https') and b'secure' not in [attr.strip().lower() for attr in res.headers[b'Set-Cookie'].split(b';')] else None)), 
    ],

    # ----------------
    # 
}

weber.analysis['basic_http'] = basic_http
# ========================================

