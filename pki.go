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

/*
- Generate a private key
- Create a CA certificate, if none exist
- Create a certificate for the given name  The private key is used as signing key.
- Generate a certificate for the given fully qualified host name, using
  the private key as host signing key and CA signing key.
This is an overly simplified PKI for testing only.
*/
func createPKI(pkiDir, cnName string) {
	if _, err := os.Stat(pkiDir); os.IsNotExist(err) {
		os.MkdirAll(pkiDir, 0770)
	}

	caFile := filepath.Join(pkiDir, "rootCA.pem")
	caKeyFile := filepath.Join(pkiDir, "rootCAKey.pem")
	casFile := filepath.Join(pkiDir, "cas.pem")
	if _, err := os.Stat(caFile); os.IsNotExist(err) {
		caPrivKey, caPubKey, err := createAndSaveKey(caKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("generated", caKeyFile)

		err = createCACert(caFile, caPrivKey, caPubKey)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("generated", caFile)

		if _, err = os.Stat(casFile); os.IsNotExist(err) {
			copyFile(casFile, caFile)
		}
	}

	keyFile := filepath.Join(pkiDir, "key.pem")
	crtFile := filepath.Join(pkiDir, "crt.pem")
	_, pubKey, err := createAndSaveKey(keyFile)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("generated", keyFile)

	rootCA, err := tls.LoadX509KeyPair(caFile, caKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	err = createCert(cnName, crtFile, &rootCA, pubKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("generated", crtFile)

	os.Exit(0)
}

func createAndSaveKey(filename string) (crypto.PrivateKey, crypto.PublicKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("createAndSaveKey: %s", err)
	}
	pub := key.Public()

	out, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("createAndSaveKey: %s", err)
	}
	defer out.Close()
	err = pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, nil, fmt.Errorf("createAndSaveKey: %s", err)
	}
	return key, pub, nil
}

func createCACert(filename string, key crypto.PrivateKey, pub crypto.PublicKey) error {
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
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6},
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
