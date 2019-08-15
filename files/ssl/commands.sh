# RESET EVERYTHING
printf 'yes\n' | ./easy-rsa/easyrsa init-pki

# CREATE CA
printf 'Weber\n' | ./easy-rsa/easyrsa build-ca nopass

# CREATE CSR FOR SERVER
printf '\n' | ./easy-rsa/easyrsa gen-req seznam.cz nopass

# GENERATE CRT FROM CSR
printf 'yes\n' | ./easy-rsa/easyrsa sign-req server seznam.cz

