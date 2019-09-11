# Creating a certificate authority

### Set up the environemt
```
mkdir -p authority/newcerts
touch ./authority/index.txt
echo '01' > ./authority/serial
```

### Create key for certificate authority
```
openssl genrsa -des3 -out ./authority/ca.key 2048
```
you will be prompted for a password, or for a non-password version, remove the -des3 option


### Create a certificate for the certificate authority
```
openssl req -new -x509 -key ./authority/ca.key -days 1024 -subj "/CN=localhost" -out ./authority/ca.crt

ln -s ./authority/ca.crt .
```

### Create a `./authority/ca.conf` file with the following content:
```
# we use 'ca' as the default section because we're usign the ca command
[ ca ]
default_ca = my_ca

[ my_ca ]
dir = ./authority

#  This file must be present and contain a valid serial number.
serial = $dir/serial

# the text database file to use. Mandatory. This file must be present though initially it will be empty.
database = $dir/index.txt

# specifies the directory where new certificates will be placed. Mandatory.
new_certs_dir = $dir/newcerts

# the file containing the CA certificate. Mandatory
certificate = $dir/ca.crt

# the file contaning the CA private key. Mandatory
private_key = $dir/ca.key

# the message digest algorithm. Remember to not use MD5
default_md = sha1

# for how many days will the signed certificate be valid
default_days = 365

# a section with a set of variables corresponding to DN fields
policy = my_policy

[ my_policy ]
# if the value is "match" then the field value must match the same field in the
# CA certificate. If the value is "supplied" then it must be present.
# Optional means it may be present. Any fields not mentioned are silently deleted.
countryName = optional
stateOrProvinceName = optional
organizationName = optional
commonName = supplied
organizationalUnitName = optional
```




### Create certificate request
```
openssl genrsa -out client1.key 2048
openssl req -new -key client1.key -subj "/CN=client1" -out client1.csr
```

### View the request
```
openssl req -in client1.csr -noout -text
```
### Generate the certificate
```
openssl ca -config ./authority/ca.conf -out client1.crt -infiles client1.csr
```

### View the certificate
```
openssl x509 -in client1.crt -noout -text
```

### Verify the certificate
```
openssl verify -CAfile ./authority/ca.crt client1.crt
```