package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func runServer(selfAddress string, serviceCert []byte, serviceCertKey []byte, caCert []byte, jt joinToken) {
	log.Println("Server starting...")

	cert, err := tls.X509KeyPair(serviceCert, serviceCertKey)
	if err != nil {
		log.Fatal("Failed to create server certificate key pair")
	}

	// setup trust service TLS listener config
	certpool := x509.NewCertPool()
	serviceTLSConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certpool,
	}

	joinServer := &http.Server{
		Addr:      selfAddress,
		Handler:   nil, // Default muxer
		TLSConfig: serviceTLSConf,
	}

	// endpoint to return the CA (this was easier than building cert chains)
	http.HandleFunc("/ca", func(res http.ResponseWriter, req *http.Request) {
		ca := caAsPEM{Bytes: caCert}
		err := json.NewEncoder(res).Encode(ca)
		if nil != err {
			panic("Failed to encode ca for client")
		}
	})

	// endpoint to allow joining node to request CA bundle and join
	http.HandleFunc("/join", func(res http.ResponseWriter, req *http.Request) {
		proof := addJoinProof{}

		// TODO (aaron-crl): [Security] make this more error resilient to size and shape attacks
		err := json.NewDecoder(req.Body).Decode(&proof)
		if err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			log.Printf("/join: Bad proof from %s\n", req.RemoteAddr)
			return
		}

		log.Printf("Received proof for alleged join-token: %x\n", proof.TokenID)

		// TODO look up token in database, verify not expired, etc
		// the original token is just provided to this function for
		// demonstration purposes

		// check if valid
		if !validJoinProof(proof, jt.sharedSecret) {
			http.Error(res, "invalid join proof", http.StatusBadRequest)
			return
		}

		log.Printf("Captured valid join for tokenID %x\n", proof.TokenID)

		// TODO acknowledge validation to client (send CA bundle)
		res.Write([]byte("<CA Bundle>"))

		// TODO mark token consumed
	})

	log.Println("Server listener starting.")
	// start the server
	log.Fatal(joinServer.ListenAndServeTLS("", ""))
}

func main() {
	selfAddress := "localhost:8443"

	// because
	testMarshalling()

	tokenID, _ := uuid.NewRandom()

	jt := joinToken{
		tokenID:      tokenID,
		sharedSecret: []byte("sUp3rS3kr!tsUp3rS3kr!tsUp3rS3kr!"), // This MUST be 32 bytes
		expiration:   time.Now().Add(time.Hour),
	}

	// Create a server with a CA and Service Certificate
	caCert, caKey := createCA()
	serverCert, serverKey, err := createServiceCerts("localhost", caCert, caKey)
	if nil != err {
		log.Fatalln(err)
	}

	go runServer(selfAddress, serverCert, serverKey, caCert, jt)

	time.Sleep(5 * time.Second)

	log.Println("Starting client test.")
	caBundle, err := getValidatedPeerCaCert(selfAddress, jt, computeHmac256(caCert, jt.sharedSecret))
	if nil != err {
		log.Fatal(err.Error())
	}

	log.Printf("CA Bundle: %s\n", caBundle)
}
