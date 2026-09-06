// Package testpki mints throwaway signing credentials for tests: a self-signed
// P-256 certificate that satisfies the C2PA certificate profile (digitalSignature
// key usage, an emailProtection EKU, not a CA), plus PEM encodings of the pair.
// It is imported only by tests and is not part of the binary.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// Credentials is a private key and the self-signed certificate for it.
type Credentials struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
}

// SelfSigned mints credentials whose certificate carries commonName and is
// valid from an hour ago for a day.
func SelfSigned(commonName string) (Credentials, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Credentials{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"c2pa-mcp tests"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return Credentials{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{Key: key, Cert: cert}, nil
}

// KeyPEM is the key as an unencrypted PKCS#8 "PRIVATE KEY" block.
func (c Credentials) KeyPEM() []byte {
	der, err := x509.MarshalPKCS8PrivateKey(c.Key)
	if err != nil {
		panic(fmt.Sprintf("testpki: marshal PKCS#8: %v", err))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// KeyPEMSEC1 is the key as a legacy "EC PRIVATE KEY" block.
func (c Credentials) KeyPEMSEC1() []byte {
	der, err := x509.MarshalECPrivateKey(c.Key)
	if err != nil {
		panic(fmt.Sprintf("testpki: marshal SEC 1: %v", err))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// CertPEM is the certificate as a "CERTIFICATE" block.
func (c Credentials) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}
