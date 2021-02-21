package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"log"
	"math/big"
	"time"

	"github.com/google/uuid"
)

type caAsPEM struct {
	Bytes []byte
}

// helper function for hmac because go makes it
// easy to screw this up
func computeHmac256(message []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

// helper function for hmac verification
func validHmac256(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

// validJoinToken is a dummy validation function.
func validJoinToken(validToken joinToken, requestToken joinToken) (bool, error) {
	if validToken.TokenID != requestToken.TokenID {
		return false, errors.New("invalid tokenID")
	}

	if time.Now().After(requestToken.Expiration) {
		return false, errors.New("expired tokenID")
	}

	if 0 != bytes.Compare(validToken.SharedSecret, requestToken.SharedSecret) {
		return false, errors.New("invalid sharedSecret")
	}

	return true, nil
}

// trust bundle builder
func createCA() (caCert []byte, caKey []byte) {
	// This function creates a short lived CA for node initialization

	notBefore := time.Now()
	notAfter := time.Now().Add(time.Hour)

	// create random serial number for CA
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	serialNumber, err := rand.Int(rand.Reader, max)
	if nil != err {
		log.Fatal("Failed to create random serial number")
	}

	// Create short lived initial CA template
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cockroach Labs"},
			Country:      []string{"US"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	// create CA certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caCert = caPEM.Bytes()
	caKey = caPrivKeyPEM.Bytes()
	return
}

func createServiceCerts(hostname string, caCertPEM []byte, caCertKeyPEM []byte) (serviceCertBytes []byte, serviceCertKeyBytes []byte, err error) {
	// Establish usage window
	notBefore := time.Now()
	notAfter := time.Now().Add(time.Hour)

	// bulid service template
	serviceCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2000),
		Subject: pkix.Name{
			Organization: []string{"Cockroach Labs"},
			Country:      []string{"US"},
		},
		DNSNames:    []string{hostname},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	caCert, rest := pem.Decode([]byte(caCertPEM))
	if 0 < len(rest) {
		log.Println("Failed to parse valid PEM from CaCertificate blob")
		return
	}

	ca, err := x509.ParseCertificate(caCert.Bytes)
	if err != nil {
		return
	}

	caCertKeyBlock, _ := pem.Decode(caCertKeyPEM)
	caCertKey, err := x509.ParsePKCS1PrivateKey(caCertKeyBlock.Bytes)
	if err != nil {
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, serviceCertTemplate, ca, &certPrivKey.PublicKey, caCertKey)
	if err != nil {
		return
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	serviceCertBytes = caPEM.Bytes()
	serviceCertKeyBytes = caPrivKeyPEM.Bytes()
	return
}

type joinToken struct {
	TokenID      uuid.UUID
	SharedSecret []byte
	Expiration   time.Time
}

func (jt joinToken) Marshal(caPublicKey []byte) string {
	id, _ := jt.TokenID.MarshalBinary()
	authFingerprint := computeHmac256(caPublicKey, jt.SharedSecret)
	token := append(id, authFingerprint...)   // 16 + 32
	token = append(token, jt.SharedSecret...) // + 32
	cSum := crc32.ChecksumIEEE(token)
	token = append(token, byte(cSum)) // + 1 Truncated checksum
	return hex.EncodeToString(token)
}

// Unmarshal function and check checksum
func unmarshalJoinToken(s string) (jt joinToken, authFingerprint []byte) {

	raw, err := hex.DecodeString(s)
	if nil != err {
		log.Fatal("Failed to decode hex encoded token.")
	}

	cSum := crc32.ChecksumIEEE(raw[:len(raw)-1])
	if byte(cSum) != raw[len(raw)-1] {
		log.Fatal("Checksum failed, possible copy/paste error.")
	}
	jt.TokenID, err = uuid.FromBytes(raw[:16])
	if nil != err {
		log.Fatal("Failed to decode tokenID.")
	}
	authFingerprint = raw[16:48]
	jt.SharedSecret = raw[48:80]

	return
}

// wrote this to maintain mental integrity
func testMarshalling() {
	caPublicKey := []byte("totallyALegitKey")

	tokenID, _ := uuid.NewRandom()

	sourceToken := joinToken{
		TokenID:      tokenID,
		SharedSecret: []byte("sUp3rS3kr!tsUp3rS3kr!tsUp3rS3kr!"),
		Expiration:   time.Time{},
	}

	stEncoded := sourceToken.Marshal(caPublicKey)

	//fmt.Println(stEncoded)

	destToken, authFP := unmarshalJoinToken(stEncoded)

	if sourceToken.TokenID != destToken.TokenID {
		log.Fatal("tokenID failed to marshal/unmarshal")
	}
	if !bytes.Equal(sourceToken.SharedSecret, destToken.SharedSecret) {
		log.Fatal("sharedSecret failed to marshal/unmarshal")
	}
	if !validHmac256(caPublicKey, authFP, destToken.SharedSecret) {
		log.Fatal("authFingerprint failed to marshal/unmarshal")
	}
}
