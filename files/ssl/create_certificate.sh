#!/bin/sh
DOMAIN=$1

# CREATE CSR FOR SERVER
MESSAGE='\n'

cd "${0%/*}"
[ -f pki/private/$1.key ] && MESSAGE='yes\n'
# no `echo -e`, because this is /bin/sh !!!
printf "$MESSAGE" | ./easy-rsa/easyrsa gen-req "$1" nopass

# GENERATE CRT FROM CSR
MESSAGE='yes\n'
printf "$MESSAGE" | ./easy-rsa/easyrsa sign-req server "$1"

