package ccptest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math"
	"math/big"
	"time"
)

// CA represents a Certificate Authority for testing
type CA struct {
	// Root Certificate
	Certificate *x509.Certificate

	// Private key of Root Certificate
	privateKey *rsa.PrivateKey
}

// NewCA creates a CA for testing client certifcates
func NewCA() (*CA, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1969),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &pk.PublicKey, pk)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return &CA{Certificate: cert, privateKey: pk}, nil
}

// NewClientCertificate creates a new test client certificate
func (ca *CA) NewClientCertificate(cn string) ([]byte, []byte, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, err
	}
	certTemplate := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	//	certBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &pk.PublicKey, pk)
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, ca.Certificate, &pk.PublicKey, ca.privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	pkPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	})

	return certPEM, pkPEM, nil
}
