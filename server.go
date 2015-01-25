package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strconv"
)

func we(w http.ResponseWriter, e error) {
	b := []byte(e.Error())
	w.Header().Add("Content-Type", "text/plain")
	w.Header().Add("Content-Length", strconv.Itoa(len(b)))
	w.Write(b)
}

type authenticator func(string, string) error

var keypair tls.Certificate
var servercert *x509.Certificate
var a authenticator

func Server(fqdn string, auth authenticator, handler func(http.ResponseWriter, *http.Request)) error {
	a = auth
	cert, err := os.Open(fqdn + ".crt")
	defer cert.Close()

	// We already have key and cert
	if err == nil {
		keypair, err = tls.LoadX509KeyPair(fqdn+".crt", fqdn+".rsa.key")
		if err != nil {
			return fmt.Errorf("failed to load x509 keypair: %v", err)
		}

		servercert, err = PEMToCertificate(cert)
		if err != nil {
			return err
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

		key, err := os.Create(fqdn + ".rsa.key")
		if err != nil {
			return err
		}
		defer key.Close()

		err = PrivateKeyToPEM(priv, key)
		if err != nil {
			return err
		}

		var c []byte
		servercert, c, err = SelfSignedPowerCertificate(priv, fqdn, []string{fqdn})
		if err != nil {
			return err
		}

		cert, err = os.Create(fqdn + ".crt")
		if err != nil {
			return err
		}
		defer cert.Close()

		err = CertificateToPEM(c, cert)
		if err != nil {
			return err
		}

		return Server(fqdn, auth, handler)
	}

	extmux := http.NewServeMux()
	extmux.HandleFunc("/secure", func(w http.ResponseWriter, rq *http.Request) {
		if len(rq.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// if a client cert was given, it has been verified (per the
		// TLS config), and so it's safe to assume the user is
		// authenticated.
		handler(w, rq)
	})
	extmux.HandleFunc("/auth", authHandler)

	pool := x509.NewCertPool()
	pool.AddCert(servercert)
	srv := http.Server{Addr: ":8443", Handler: extmux, TLSConfig: &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,

		// If you want to be able to inspect with Wireshark, uncomment:
		//CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}}

	// This will call x509.LoadX509KeyPair again unfortunately, but it's
	// startup cost, so meh.
	return srv.ListenAndServeTLS(fqdn+".crt", fqdn+".rsa.key")
}

func authHandler(w http.ResponseWriter, rq *http.Request) {
	err := rq.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		we(w, err)
		return
	}

	if rq.PostForm.Get("key") == "" {
		w.WriteHeader(http.StatusBadRequest)
		we(w, fmt.Errorf("no public key given to sign"))
		return
	}

	err = a(rq.PostForm.Get("username"), rq.PostForm.Get("password"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		we(w, err)
		return
	}

	pub, err := HTMLKeygenKeyToPubkey(rq.PostForm.Get("key"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		we(w, err)
	}

	_, cbytes, err := SignedCertificateFor(keypair.PrivateKey, servercert, pub, rq.PostForm.Get("username"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		we(w, err)
		return
	}

	w.Header().Add("Content-Type", "application/x-x509-user-cert")
	w.Header().Add("Content-Length", strconv.Itoa(len(cbytes)))
	w.Write(cbytes)
}
