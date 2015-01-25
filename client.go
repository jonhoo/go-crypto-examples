package keys

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

func Client(user string, fqdn string, do func(*http.Client)) error {
	var keypair tls.Certificate
	key, err := os.Open(user + ".rsa.key")
	defer key.Close()

	// We already have key and cert
	if err == nil {
		keypair, err = tls.LoadX509KeyPair(user+".crt", user+".rsa.key")
		if err != nil {
			return fmt.Errorf("failed to load x509 keypair: %v", err)
		}
	} else {
		// We need a new key and cert
		if _, ok := err.(*os.PathError); !ok {
			return err
		}

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		pubkey, err := PubkeyAsHTMLKeygen(priv, user, x509.SHA512WithRSA)
		if err != nil {
			return err
		}

		c := newClient(fqdn, nil)
		data := make(url.Values)
		data.Set("username", user)
		data.Set("password", "secret")
		data.Set("key", pubkey)

		res, err := c.PostForm("https://"+fqdn+":8443/auth", data)
		if err != nil {
			return err
		}
		defer res.Body.Close()

		var buf bytes.Buffer
		buf.ReadFrom(res.Body)

		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("%s: %s", res.Status, buf.String())
		}

		key, err := os.Create(user + ".rsa.key")
		if err != nil {
			return err
		}
		defer key.Close()

		err = PrivateKeyToPEM(priv, key)
		if err != nil {
			return err
		}

		cert, err := os.Create(user + ".crt")
		if err != nil {
			return err
		}
		defer cert.Close()

		err = CertificateToPEM(buf.Bytes(), cert)
		if err != nil {
			return err
		}

		return Client(user, fqdn, do)
	}

	c := newClient(fqdn, &keypair)
	go do(c)
	return nil
}

func newClient(server string, c *tls.Certificate) *http.Client {
	conf := &tls.Config{
		ServerName: server,
		RootCAs:    nil,

		// TODO: testing only
		InsecureSkipVerify: true,

		// To inspect with Wireshark, uncomment:
		// CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}

	if c != nil {
		conf.Certificates = []tls.Certificate{*c}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: conf,
		},
	}
}
