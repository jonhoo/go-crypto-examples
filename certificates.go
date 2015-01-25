package keys

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

func SignedCertificateFor(signerPkey interface{}, signerCert *x509.Certificate, signee interface{}, cname string) (*x509.Certificate, []byte, error) {
	cert := &x509.Certificate{
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA512WithRSA,
		SerialNumber:          big.NewInt(4000),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		Subject: pkix.Name{
			Country:      []string{"Earth"},
			Organization: []string{"Skynet"},
			CommonName:   cname,
		},
	}
	c, e := x509.CreateCertificate(rand.Reader, cert, signerCert, signee, signerPkey)
	if e != nil {
		return nil, c, e
	}

	cert, e = x509.ParseCertificate(c)
	return cert, c, e
}

func SelfSignedPowerCertificate(priv interface{}, cname string, domains []string) (*x509.Certificate, []byte, error) {
	cert := &x509.Certificate{
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA512WithRSA,
		SerialNumber:          big.NewInt(1338),
		SubjectKeyId:          []byte{1, 3, 3, 7},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		DNSNames:              domains,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		Subject: pkix.Name{
			Country:      []string{"Earth"},
			Organization: []string{"Skynet"},
			CommonName:   cname,
		},
	}

	pub, err := PublicKey(priv)
	if err != nil {
		return nil, nil, err
	}

	c, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if e != nil {
		return nil, nil, fmt.Errorf("failed to build certificate: %v", e)
	}

	cert, e = x509.ParseCertificate(c)
	return cert, c, e
}

func PublicKey(priv interface{}) (interface{}, error) {
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		return &priv.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &priv.PublicKey, nil
	default:
		return nil, fmt.Errorf("could not determine public key for private key %v", priv)
	}
}
