package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
)

func getHostRootCaCert(host string) (caCertBytes []byte, err error) {
	log.Println("Starting to attempt to get peer root CA")

	// connect to HTTPS endpoint unverified (effectively HTTP) for CA
	clientTransport := http.DefaultTransport.(*http.Transport).Clone()
	clientTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: clientTransport}

	res, err := client.Get("https://" + host + "/ca")
	if nil != err {
		return
	}
	defer res.Body.Close()

	ca := caAsPEM{}
	err = json.NewDecoder(res.Body).Decode(&ca)
	caCertBytes = ca.Bytes

	return
}

func getValidatedPeerCaCert(peerAddress string, jt joinToken, authFingerprint []byte) (caBundle string, err error) {
	caBundle = "No bundle received."

	caCertBytes, err := getHostRootCaCert(peerAddress)
	if nil != err {
		return
	}

	// validate CA is trusted
	// HMAC(hostname + node CA public certificate, secretToken)
	if !validHmac256(caCertBytes, authFingerprint, jt.sharedSecret) {
		err = errors.New("untrusted CA, possible security issue")
		return
	}

	// ADD CA to pool
	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(caCertBytes)
	_ = &tls.Config{
		RootCAs: certpool,
	}

	log.Println("CA is valid, starting proof")
	// compute proof
	id, _ := jt.tokenID.MarshalBinary()
	mac := computeHmac256(id, jt.sharedSecret)
	proof := addJoinProof{
		TokenID: id,
		MAC:     mac,
	}

	// Request bundle with proof
	// connect to HTTPS endpoint unverified (effectively HTTP) for CA
	clientTransport := http.DefaultTransport.(*http.Transport).Clone()
	clientTransport.TLSClientConfig = &tls.Config{RootCAs: certpool}
	client := &http.Client{Transport: clientTransport}

	body := new(bytes.Buffer)
	json.NewEncoder(body).Encode(proof)
	res, err := client.Post("https://"+peerAddress+"/join", "application/json; charset=utf-8", body)
	if nil != err {
		return
	}
	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)

	caBundle = string(b)

	return
}
