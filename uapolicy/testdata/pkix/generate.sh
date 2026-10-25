#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Regenerates the certificate request and CRL fixtures of
# uapolicy/x509_csr_test.go and uapolicy/x509_crl_test.go with the openssl CLI
# (made with OpenSSL 4.0.3):
#
#   <curve>-csr.pem  a PKCS #10 request with a subjectAltName extension
#   <curve>-ca.pem   a self-signed CA certificate (keyCertSign, cRLSign)
#   <curve>-crl.pem  a v2 CRL of that CA revoking serial 0x1001 (keyCompromise)
#
#   cd uapolicy/testdata/pkix && ./generate.sh
set -eu

OPENSSL=${OPENSSL:-openssl}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/ca.cnf" <<EOF
[ ca ]
default_ca = test_ca

[ test_ca ]
database         = $tmp/index.txt
crlnumber        = $tmp/crlnumber
default_md       = default
default_crl_days = 36500
crl_extensions   = crl_ext

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

for curve in brainpoolP256r1 brainpoolP384r1 ed448; do
	case $curve in
	ed448) set -- -algorithm ED448 ;;
	*) set -- -algorithm EC -pkeyopt "ec_paramgen_curve:$curve" ;;
	esac

	"$OPENSSL" genpkey "$@" -out "$tmp/$curve-leaf.key"
	"$OPENSSL" req -new -key "$tmp/$curve-leaf.key" -subj "/CN=csr-$curve/O=uapolicy" \
		-addext "subjectAltName=URI:urn:csr:$curve,DNS:localhost" -out "$curve-csr.pem"

	"$OPENSSL" genpkey "$@" -out "$tmp/$curve-ca.key"
	"$OPENSSL" req -x509 -new -key "$tmp/$curve-ca.key" -subj "/CN=ca-$curve/O=uapolicy" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" -days 36500 -out "$curve-ca.pem"

	printf 'R\t491231235959Z\t240101000000Z,keyCompromise\t1001\tunknown\t/CN=revoked\n' >"$tmp/index.txt"
	echo 01 >"$tmp/crlnumber"
	"$OPENSSL" ca -config "$tmp/ca.cnf" -gencrl -keyfile "$tmp/$curve-ca.key" -cert "$curve-ca.pem" -out "$curve-crl.pem"
done
