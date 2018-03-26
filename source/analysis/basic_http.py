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
    #      lambda req,res:(('Category', 'Message') or None)
    #     )
    'rr_tests': [

        ('Missing Content-Type', ['http'], lambda req,res:(('WARNING', 'Content-Type is not defined.') if res and not res.headers.get(b'Content-Type') else None)),

        ('PHP returned', ['http'], lambda req,res:(('SECURITY', 'PHP code returned from server.') if res and is_content_type_text(res.headers.get(b'Content-Type')) and res.find_tags(startends=[(b'<?', b'?>')], valueonly=False) else None)),
    ],

    # ----------------
    # 
}

weber.analysis['basic_http'] = basic_http
# ========================================

