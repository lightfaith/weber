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
    #      ('Category', 'Message', certainity) in case all conditions match
    #      [list of supported protocols (SSL variants excluded)], 
    #      [list of ('comment', 'condition'))
    #                                ` lambda req,res,uri: True or False # whether the problem is found
    #     )
    'rr_tests': [
        (   'NO_CONTENT-TYPE', 
            ('WARNING', 'Content-Type is not defined.', True),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res),
                ('content-type missing', lambda _,res,__: not res.headers.get(b'Content-Type')),
                ('data or 2xx', lambda _,res,__: (len(res.data.strip())>0 or res.statuscode <300)),
            ]
        ),
        (   'PHP_CODE', 
            ('SECURITY', 'PHP code returned from server.', False),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res), 
                ('textual content-type', lambda _,res,__: is_content_type_text(res.headers.get(b'Content-Type'))),
                ('data', lambda _,res,__: res.data),
                ('php tag inside', lambda _,res,__: any(tag in res.data for tag in (b'<?php', b'<? ', b'<?\t', b'<?\n', b'<?\r'))),
            ]
        ),
        (   'COOKIE_NO_HTTPONLY',
            ('SECURITY', 'Cookie does not have \'HttpOnly\' attribute.', True),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res),
                ('set-cookie header', lambda _,res,__: res.headers.get(b'Set-Cookie')),
                ('no httponly in set-cookie', lambda _,res,__: b'httponly' not in [attr.strip().lower() for attr in res.headers[b'Set-Cookie'].split(b';')]),
            ]
        ),
        (   'COOKIE_NO_SECURE', 
            ('SECURITY', 'Cookie set over SSL but without \'secure\' attribute.', True),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res),
                ('set-cookie header', lambda _,res,__: b'Set-Cookie' in res.headers.keys()),
                ('over SSL', lambda _,__,uri: uri.scheme in ('https',)),
                ('no secure in set-cookie', lambda _,res,__: b'secure' not in [attr.strip().lower() for attr in res.headers.get(b'Set-Cookie').split(b';')]),
            ]
        ),
        (   'HSTS_OVER_HTTP', 
            ('SECURITY', 'HSTS header is sent over HTTP.', True),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res),
                ('hsts header', lambda _,res,__: b'Strict-Transport-Security' in res.headers.keys()),
                ('over HTTP', lambda _,__,uri: uri.scheme in ('http',)),
            ]
        ),
        (   'NO_HSTS', 
            ('SECURITY', 'HSTS header is not used.', True),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res),
                ('over SSL', lambda _,__,uri: uri.scheme in ('https',)),
                ('no hsts header', lambda _,res,__: b'Strict-Transport-Security' not in res.headers.keys()),
            ]
        ),
        (   'X-POWERED-BY_HEADER', 
            ('INFOLEAK', 'X-Powered-By header is included.', False),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res),
                ('x-powered-by header', lambda _,res,__: b'X-Powered-By' in res.headers.keys()),
            ]
        ),
        (   'AUTHORIZATION_OVER_HTTP', 
            ('SECURITY', 'Authorization is desired over HTTP connection.', True),
            ['http'], 
            [
                ('response exists', lambda _,res,__: res),
                ('401 code', lambda _,res,__: res.statuscode == 401),
                ('over HTTP', lambda _,__,uri: uri.scheme in ('http',)),
            ]
        ),
    ],
    # ----------------
    # 
}

weber.analysis['basic_http'] = basic_http
# ========================================

