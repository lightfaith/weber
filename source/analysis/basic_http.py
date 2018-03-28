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
    #      ('Category', 'Message') in case all conditions match
    #      [list of supported protocols (SSL variants excluded)], 
    #      [list of ('comment', 'condition'))
    #                                ` lambda req,res,uri: True or False # whether the problem is found
    #     )
    'rr_tests': [
        (   'Missing Content-Type', 
            ('WARNING', 'Content-Type is not defined.'),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res),
                ('content-type missing', lambda _,res,__: not res.headers.get(b'Content-Type')),
                ('data or 2xx', lambda _,res,__: (len(res.data.strip())>0 or res.statuscode <300)),
            ]
        ),
        (   'PHP returned', 
            ('SECURITY', 'PHP code returned from server.'),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res), 
                ('textual content-type', lambda _,res,__: is_content_type_text(res.headers.get(b'Content-Type'))),
                ('data', lambda _,res,__: res.data),
                ('php tag inside', lambda _,res,__: any(tag in res.data for tag in (b'<?php', b'<? ', b'<?\t', b'<?\n', b'<?\r'))),
            ]
        ),
        (   'Cookie without \'HttpOnly\' attribute',
            ('SECURITY', 'Cookie does not have \'HttpOnly\' attribute.'),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res),
                ('set-cookie header', lambda _,res,__: res.headers.get(b'Set-Cookie')),
                ('no httponly in set-cookie', lambda _,res,__: b'httponly' not in [attr.strip().lower() for attr in res.headers[b'Set-Cookie'].split(b';')]),
            ]
        ),
        (   'Cookie without \'secure\' attribute', 
            ('SECURITY', 'Cookie set over SSL but without \'secure\' attribute.'),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res),
                ('set-cookie header', lambda _,res,__: b'Set-Cookie' in res.headers.keys()),
                ('over SSL', lambda _,res,uri: uri.scheme in ('https')),
                ('no secure in set-cookie', lambda _,res,__: b'secure' not in [attr.strip().lower() for attr in res.headers.get(b'Set-Cookie').split(b';')]),
            ]
        ),
    ],
    # ----------------
    # 
}
""" # lambda as third argument
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
            ('set-cookie header', res.headers.get(b'Set-Cookie')),
           #('no httponly in set-cookie', 'httponly' not in [attr.strip().lower() for attr in res.headers[b'Set-Cookie'].split(b';')]),
            ]) else None)),

        ('Cookie without \'secure\' attribute', ['http'], lambda _,res,uri:(('SECURITY', 'Cookie set over SSL but without \'secure\' attribute.') if all(is_true(comment, expression) for comment,expression in [
            ('response exists', res),
            ('set-cookie header', b'Set-Cookie' in res.headers.keys()),
            ('over SSL', uri.scheme in ('https')),
            ('no secure in set-cookie', b'secure' not in [attr.strip().lower() for attr in res.headers.get(b'Set-Cookie').split(b';')]),
            ]) else None)),
    ],
    """

weber.analysis['basic_http'] = basic_http
# ========================================

