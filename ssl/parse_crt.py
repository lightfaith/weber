#!/usr/bin/python3
import ssl
#from M2Crypto.X509 import load_cert_string
from OpenSSL.crypto import FILETYPE_PEM, load_certificate
import sys

addr = sys.argv[1]
domain, _, port = addr.partition(':')
try:
    port = int(port)
except:
    port = 443
cert = ssl.get_server_certificate((domain, port))

x509 = load_certificate(FILETYPE_PEM, cert)
components = {k.decode(): v.decode() 
              for k,v in x509.get_subject().get_components()}
for component in ['C', 'ST', 'L', 'O', 'CN']:
    print(components.get(component) or '')


