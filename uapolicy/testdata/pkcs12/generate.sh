#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Regenerates the PKCS #12 fixtures of uapolicy/pfx_test.go with the openssl
# CLI (made with OpenSSL 4.0.3; the RC2 and 2-key 3DES files need its legacy
# provider). Every file holds one private key and its self-signed certificate;
# rsa-chain.p12 also holds the issuing CA certificate. The password is "opcua"
# unless the name says otherwise.
#
#   cd uapolicy/testdata/pkcs12 && ./generate.sh
set -eu

OPENSSL=${OPENSSL:-openssl}
PASS=opcua
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

key() { # key <name> <genpkey arguments...>
	name=$1
	shift
	"$OPENSSL" genpkey "$@" -out "$tmp/$name.key"
	"$OPENSSL" req -x509 -new -key "$tmp/$name.key" -subj "/CN=pfx-$name/O=uapolicy" \
		-addext "subjectAltName=URI:urn:pfx:$name" -days 36500 -out "$tmp/$name.crt"
}

export_pfx() { # export_pfx <out> <key> <password> <pkcs12 arguments...>
	out=$1 name=$2 pass=$3
	shift 3
	"$OPENSSL" pkcs12 -export -inkey "$tmp/$name.key" -in "$tmp/$name.crt" \
		-passout "pass:$pass" "$@" -out "$out"
}

key rsa -algorithm RSA -pkeyopt rsa_keygen_bits:2048
key p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
key bp256 -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256r1
key bp384 -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP384r1
key ed25519 -algorithm ED25519
key ed448 -algorithm ED448

# OpenSSL 3 defaults: PBES2 (PBKDF2 HMAC-SHA256, AES-256-CBC) for the key and
# the certificates, HMAC-SHA256 MAC.
export_pfx rsa-default.p12 rsa $PASS
export_pfx p256-default.p12 p256 $PASS
export_pfx brainpoolP256r1-default.p12 bp256 $PASS
export_pfx brainpoolP384r1-default.p12 bp384 $PASS
export_pfx ed25519-default.p12 ed25519 $PASS
export_pfx ed448-default.p12 ed448 $PASS

# Legacy (OpenSSL 1.x and Windows): pbeWithSHAAnd3-KeyTripleDES-CBC for the
# key, pbeWithSHAAnd40BitRC2-CBC for the certificates, HMAC-SHA1 MAC.
export_pfx rsa-legacy.p12 rsa $PASS -legacy
export_pfx brainpoolP256r1-legacy.p12 bp256 $PASS -legacy

# The other PKCS #12 PBE schemes and MAC digests.
export_pfx p256-2des-rc2-128.p12 p256 $PASS -provider legacy -provider default \
	-keypbe PBE-SHA1-2DES -certpbe PBE-SHA1-RC2-128 -macalg sha512
export_pfx ed448-3des-sha384.p12 ed448 $PASS -provider legacy -provider default \
	-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha384 -iter 1000
export_pfx ed25519-sha224.p12 ed25519 $PASS -macalg sha224

# PBES2 with other ciphers.
export_pfx p256-pbes2-des3-aes128.p12 p256 $PASS -keypbe des-ede3-cbc -certpbe aes-128-cbc
export_pfx bp384-pbes2-aes192.p12 bp384 $PASS -keypbe aes-192-cbc -certpbe aes-192-cbc

# PBMAC1 (RFC 9579) instead of the PKCS #12 MAC.
export_pfx rsa-pbmac1.p12 rsa $PASS -pbmac1_pbkdf2
export_pfx ed448-pbmac1-sha512.p12 ed448 $PASS -pbmac1_pbkdf2 -pbmac1_pbkdf2_md sha512

# No encryption at all (keyBag, certificates in plain data), and no MAC.
export_pfx p256-noenc.p12 p256 $PASS -keypbe NONE -certpbe NONE
export_pfx ed25519-nomac.p12 ed25519 $PASS -nomac
export_pfx p256-noenc-nomac.p12 p256 "" -keypbe NONE -certpbe NONE -nomac

# An empty password.
export_pfx rsa-emptypass.p12 rsa ""
export_pfx bp256-emptypass-legacy.p12 bp256 "" -legacy

# A chain: leaf key and certificate plus the CA certificate.
key ca -algorithm EC -pkeyopt ec_paramgen_curve:P-256
"$OPENSSL" req -new -key "$tmp/rsa.key" -subj "/CN=pfx-rsa-leaf/O=uapolicy" -out "$tmp/leaf.csr"
"$OPENSSL" x509 -req -in "$tmp/leaf.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -days 36500 -out "$tmp/leaf.crt"
"$OPENSSL" pkcs12 -export -inkey "$tmp/rsa.key" -in "$tmp/leaf.crt" -certfile "$tmp/ca.crt" \
	-passout "pass:$PASS" -out rsa-chain.p12
