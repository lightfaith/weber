#!/bin/bash
DOMAIN=$1

cd ssl
# CREATE CSR FOR SERVER
MESSAGE='\n'
[ -f pki/private/$1.key ] && MESSAGE='yes\n'
echo -e "$MESSAGE" | ./easy-rsa/easyrsa gen-req "$1" nopass

# GENERATE CRT FROM CSR
MESSAGE='yes'
echo -e "$MESSAGE" | ./easy-rsa/easyrsa sign-req server "$1"

