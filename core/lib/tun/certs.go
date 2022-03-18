package tun

// adapted from https://gist.github.com/samuel/8b500ddd3f6118d052b5e6bc16bc4c09

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// GenCerts generate a CA cert or a server cert signed by CA cert
// if isCA is true, the outfile will be a CA cert/key named as ca-cert.pem/ca-key.pem
// if isCA is false, the outfile will be named as is, for example, outfile-cert.pem, outfile-key.pem
func GenCerts(hosts []string, outname string, isCA bool) (err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 3650),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	var (
		cakey    *ecdsa.PrivateKey
		cacrt    *x509.Certificate
		derBytes []byte
	)

	// valid for these names
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		outname = "ca"
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
		if err != nil {
			return fmt.Errorf("Failed to create certificate: %v", err)
		}
	} else {
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, h)
			}
		}

		ca_data, err := ioutil.ReadFile("ca-key.pem")
		if err != nil {
			return fmt.Errorf("Read ca-key.pem: %v", err)
		}
		block, _ := pem.Decode(ca_data)
		cakey, _ = x509.ParseECPrivateKey(block.Bytes)

		ca_data, err = ioutil.ReadFile("ca-key.pem")
		if err != nil {
			return fmt.Errorf("Read ca-key.pem: %v", err)
		}
		block, _ = pem.Decode(ca_data)
		cacrt, _ = x509.ParseCertificate(block.Bytes)

		// generate
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, cacrt, publicKey(priv), cakey)
		if err != nil {
			return fmt.Errorf("Failed to create certificate: %v", err)
		}
	}

	// output to pem files
	out := &bytes.Buffer{}
	outcert := fmt.Sprintf("%s-cert.pem", outname)
	outkey := fmt.Sprintf("%s-key.pem", outname)
	// cert
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	err = ioutil.WriteFile(outcert, out.Bytes(), 0600)
	if err != nil {
		return fmt.Errorf("Write %s: %v", outcert, err)
	}
	out.Reset()

	// key
	pem.Encode(out, pemBlockForKey(priv))
	err = ioutil.WriteFile(outname, out.Bytes(), 0600)
	if err != nil {
		return fmt.Errorf("Write %s: %v", outkey, err)
	}

	return
}

func SignCertWithCA(cafile, cert_to_sign string) (err error) {
	return
}
