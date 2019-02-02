# RESET EVERYTHING
echo 'yes\n' | ./easy-rsa/easyrsa init-pki

# CREATE CA
echo -e 'Weber\n' | ./easy-rsa/easyrsa build-ca nopass

# CREATE CSR FOR SERVER
echo | ./easy-rsa/easyrsa gen-req seznam.cz nopass

# GENERATE CRT FROM CSR
echo 'yes' | ./easy-rsa/easyrsa sign-req server seznam.cz

