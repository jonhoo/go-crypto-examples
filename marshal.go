package keys

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
)

func PubkeyAsHTMLKeygen(prkey interface{}, challenge string, algo x509.SignatureAlgorithm) (string, error) {
	pubkey, err := PublicKey(prkey)
	if err != nil {
		return "", err
	}

	pkixbytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}

	var key SignedPublicKeyAndChallenge
	key.PublicKeyAndChallenge.Challenge = challenge
	_, err = asn1.Unmarshal(pkixbytes, &key.PublicKeyAndChallenge.Spki)
	if err != nil {
		return "", err
	}

	pkac, err := asn1.Marshal(key.PublicKeyAndChallenge)
	if err != nil {
		return "", err
	}

	h, ai, err := signingParamsForPublicKey(pubkey, algo)
	w := h.New()
	w.Write(pkac)
	digest := w.Sum(nil)

	var sig []byte
	switch prkey := prkey.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, prkey, h, digest)
	default:
		err = fmt.Errorf("cannot sign using private key type %v", prkey)
	}
	if err != nil {
		return "", err
	}

	key.Signature = asn1.BitString{sig, len(sig) * 8}
	key.SignatureAlgorithm = ai

	asnkey, err := asn1.Marshal(key)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(asnkey), nil
}

// x509.pemBlockForKey
func PrivateKeyToPEM(priv interface{}, dest io.Writer) error {
	var priv_blk pem.Block
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		priv_blk = pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *ecdsa.PrivateKey:
		b, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			return e
		}

		priv_blk = pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: b,
		}
	}

	return pem.Encode(dest, &priv_blk)
}

func CertificateToPEM(cert []byte, dest io.Writer) error {
	cert_blk := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	return pem.Encode(dest, &cert_blk)
}
