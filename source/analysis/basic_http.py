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
from source.analysis.analysis import is_true

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
        ('Missing Content-Type', ['http'], lambda _,res,__:(('WARNING', 'Content-Type is not defined.') if all(is_true(comment, expression) for comment,expression in [
            ('response exists', res),
            ('content-type missing', not res.headers.get(b'Content-Type')),
            ('data or 2xx', (len(res.data.strip())>0 or res.statuscode <300)),
            ]) else None)),

        ('PHP returned', ['http'], lambda _,res,__:(('SECURITY', 'PHP code returned from server.') if all(is_true(comment, expression) for comment,expression in [
            ('response exists', res), 
            ('textual content-type', is_content_type_text(res.headers.get(b'Content-Type'))),
            ('data', res.data),
            ('php tag inside', any(tag in res.data for tag in (b'<?php', b'<? ', b'<?\t', b'<?\n', b'<?\r'))),
            ]) else None)),

        ('Cookie without \'HttpOnly\' attribute', ['http'], lambda _,res,__:(('SECURITY', 'Cookie does not have \'HttpOnly\' attribute.') if all(is_true(comment, expression) for comment,expression in [
            ('response exists', res),
            ('set-cookie header', res.headers.get(b'Set-Cookie') is not None),
            ('no httponly in set-cookie', 'httponly' not in [attr.strip().lower() for attr in res.headers[b'Set-Cookie'].split(b';')]),
            ]) else None)),

        ('Cookie without \'secure\' attribute', ['http'], lambda _,res,uri:(('SECURITY', 'Cookie set over SSL but without \'secure\' attribute.') if all(is_true(comment, expression) for comment,expression in [
            ('response exists', res),
            ('set-cookie header', res.headers.get(b'Set-Cookie')),
            ('over SSL', uri.scheme in ('https')),
            ('no secure in set-cookie', b'secure' not in [attr.strip().lower() for attr in res.headers[b'Set-Cookie'].split(b';')]),
            ]) else None)),
    ],

    # ----------------
    # 
}

weber.analysis['basic_http'] = basic_http
# ========================================

