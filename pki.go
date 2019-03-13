package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	rootCAKeyFilename = filepath.Join("pki", "rootCA.key")
	rootCACRTFilename = filepath.Join("pki", "rootCA.crt")
	clientKeyFilename = filepath.Join("pki", "client.key")
	clientCRTFilename = filepath.Join("pki", "client.crt")
	serverKeyFilename = filepath.Join("pki", "server.key")
	serverCRTFilename = filepath.Join("pki", "server.crt")
)

func createPKI() {
	if _, err := os.Stat("pki"); os.IsNotExist(err) {
		os.Mkdir("pki", 0770)
	}

	rootCAKey, rootCAPub, err := createAndSaveKey(rootCAKeyFilename)
	if err != nil {
		log.Fatal(err)
	}
	err = createRootCACert(rootCACRTFilename, rootCAKey, rootCAPub)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("generated 'rootCA.key' and 'rootCA.crt'")

	rootCA, err := tls.LoadX509KeyPair(rootCACRTFilename, rootCAKeyFilename)
	if err != nil {
		log.Fatal(err)
	}

	_, clientPub, err := createAndSaveKey(clientKeyFilename)
	if err != nil {
		log.Fatal(err)
	}
	err = createCert("client", clientCRTFilename, &rootCA, clientPub)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("generated 'client.key' and 'client.crt'")

	_, serverPub, err := createAndSaveKey(serverKeyFilename)
	if err != nil {
		log.Fatal(err)
	}
	err = createCert("server", serverCRTFilename, &rootCA, serverPub)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("generated 'server.key' and 'server.crt'")
	os.Exit(0)
}

func createAndSaveKey(filename string) (crypto.PrivateKey, crypto.PublicKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generateAndSaveKeys: %s", err)
	}
	pub := key.Public()

	out, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("generateAndSaveKeys: %s", err)
	}
	defer out.Close()
	err = pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, nil, fmt.Errorf("generateAndSaveKeys: %s", err)
	}
	return key, pub, nil
}

func createRootCACert(filename string, key crypto.PrivateKey, pub crypto.PublicKey) error {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"ORGANIZATION_NAME"},
			Country:       []string{"COUNTRY_CODE"},
			Province:      []string{"PROVINCE"},
			Locality:      []string{"CITY"},
			StreetAddress: []string{"ADDRESS"},
			PostalCode:    []string{"POSTAL_CODE"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		return fmt.Errorf("createRootCACert: %s", err)
	}

	out, err := os.Create(filename)
	defer out.Close()
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return fmt.Errorf("createRootCACert: %s", err)
	}
	return nil
}

func createCert(cname, filename string, rootCA *tls.Certificate, pub crypto.PublicKey) error {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject:      pkix.Name{CommonName: cname},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	caCert, err := x509.ParseCertificate(rootCA.Certificate[0])
	if err != nil {
		return fmt.Errorf("createCert: %s", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, pub, rootCA.PrivateKey)
	if err != nil {
		return fmt.Errorf("createCert: %s", err)
	}

	out, err := os.Create(filename)
	defer out.Close()
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return fmt.Errorf("createCert: %s", err)
	}
	return nil
}
