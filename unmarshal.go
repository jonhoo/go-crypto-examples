package keys

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
)

func HTMLKeygenKeyToPubkey(postedKey string) (pub interface{}, err error) {
	// see https://html.spec.whatwg.org/multipage/forms.html#the-keygen-element
	signedPublicKeyAndChallenge64 := postedKey
	signedPublicKeyAndChallenge, err := base64.StdEncoding.DecodeString(signedPublicKeyAndChallenge64)
	if err != nil {
		return nil, err
	}

	var key SignedPublicKeyAndChallenge
	_, err = asn1.Unmarshal(signedPublicKeyAndChallenge, &key)
	if err != nil {
		return nil, err
	}

	spkib, err := asn1.Marshal(key.PublicKeyAndChallenge.Spki)
	if err != nil {
		return nil, err
	}

	return x509.ParsePKIXPublicKey(spkib)
}

func PEMToPrivateKey(in io.Reader) (interface{}, error) {
	var buf bytes.Buffer
	_, e := buf.ReadFrom(in)
	if e != nil {
		return nil, fmt.Errorf("failed to read private key buffer: %v", e)
	}

	block, _ := pem.Decode([]byte(buf.Bytes()))
	if block == nil {
		return nil, fmt.Errorf("certificate file was empty")
	}

	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("file is not a valid private key file; has type %v", block.Type)
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	}

	return nil, fmt.Errorf("unknown private key type %v", block.Type)
}

func PEMToCertificate(in io.Reader) (*x509.Certificate, error) {
	var buf bytes.Buffer
	buf.ReadFrom(in)
	block, _ := pem.Decode([]byte(buf.Bytes()))
	if block == nil {
		return nil, fmt.Errorf("certificate file was empty")
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, fmt.Errorf("file is not a valid certificate; has type %v", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}
