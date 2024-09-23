package tun

// adapted from https://gist.github.com/samuel/8b500ddd3f6118d052b5e6bc16bc4c09

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	CA_CERT_FILE = "ca-cert.pem"
	CA_KEY_FILE  = "ca-key.pem"
)

// PEM encoded server public key
var ServerPubKey string

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
// Returns public key bytes
func GenCerts(
	hosts []string,
	outname string,
	isCA bool,
) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("GenerateKey: %v", err)
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
		template.Subject = pkix.Name{
			Organization: []string{"ACME CA Co"},
		}
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		outname = "ca"
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate: %v", err)
		}
	} else {
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, h)
			}
		}

		// ca key file
		ca_data, err := os.ReadFile(CA_KEY_FILE)
		if err != nil {
			return nil, fmt.Errorf("read %s: %v", CA_KEY_FILE, err)
		}
		block, _ := pem.Decode(ca_data)
		cakey, _ = x509.ParseECPrivateKey(block.Bytes)

		// ca cert file
		ca_data, err = os.ReadFile(CA_CERT_FILE)
		if err != nil {
			return nil, fmt.Errorf("read %s: %v", CA_CERT_FILE, err)
		}
		block, _ = pem.Decode(ca_data)
		cacrt, _ = x509.ParseCertificate(block.Bytes)

		// generate server certificate, signed by our CA
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, cacrt, publicKey(priv), cakey)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate: %v", err)
		}
	}

	// output to pem files
	out := &bytes.Buffer{}
	outcert := fmt.Sprintf("%s-cert.pem", outname)
	outkey := fmt.Sprintf("%s-key.pem", outname)
	// cert
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	err = os.WriteFile(outcert, out.Bytes(), 0o600)
	if err != nil {
		return nil, fmt.Errorf("write %s: %v", outcert, err)
	}
	out.Reset()

	// key
	pem.Encode(out, pemBlockForKey(priv))
	err = os.WriteFile(outkey, out.Bytes(), 0o600)
	if err != nil {
		return nil, fmt.Errorf("write %s: %v", outkey, err)
	}

	// retrieve public key
	pubkey := priv.PublicKey
	// encode public key
	pubkey_data, err := x509.MarshalPKIXPublicKey(&pubkey)
	if err != nil {
		log.Printf("EncodePublicKey: %v", err)
		return nil, fmt.Errorf("encode public key: %v", err)
	}
	pubkey_out := &bytes.Buffer{}
	err = pem.Encode(pubkey_out, &pem.Block{Type: "PUBLIC KEY", Bytes: pubkey_data})
	pubkey_data = pubkey_out.Bytes()

	return pubkey_data, err
}

// NamesInCert find domain names and IPs in server certificate
func NamesInCert(cert_file string) (names []string) {
	cert, err := ParseCertPemFile(cert_file)
	if err != nil {
		log.Printf("ParseCert %s: %v", cert_file, err)
		return
	}
	for _, netip := range cert.IPAddresses {
		ip := netip.String()
		names = append(names, ip)
	}
	names = append(names, cert.DNSNames...)

	return
}

func ParsePem(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	return x509.ParseCertificate(block.Bytes)
}

// ParseKeyPemFile read from PEM file and return parsed cert
func ParseKeyPemFile(key_file string) (cert *ecdsa.PrivateKey, err error) {
	data, err := os.ReadFile(key_file)
	if err != nil {
		err = fmt.Errorf("read %s: %v", key_file, err)
		return
	}
	block, _ := pem.Decode(data)

	return x509.ParseECPrivateKey(block.Bytes)
}

// ParseCertPemFile read from PEM file and return parsed cert
func ParseCertPemFile(cert_file string) (cert *x509.Certificate, err error) {
	cert_data, err := os.ReadFile(cert_file)
	if err != nil {
		err = fmt.Errorf("read %s: %v", cert_file, err)
		return
	}
	return ParsePem(cert_data)
}

// GetFingerprint return SHA256 fingerprint of a cert
func GetFingerprint(cert_file string) string {
	cert, err := ParseCertPemFile(cert_file)
	if err != nil {
		log.Printf("GetFingerprint: ParseCert %s: %v", cert_file, err)
		return ""
	}
	return SHA256SumRaw(cert.Raw)
}

// Generate a new key pair for use with openssh
func GenerateSSHKeyPair() (privateKey, publicKey []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		err = fmt.Errorf("GenerateKey: %v", err)
		return

	}
	// pem encode
	priv_buf := new(bytes.Buffer)
	pem.Encode(priv_buf, pemBlockForKey(priv))
	privateKey = priv_buf.Bytes()

	// public
	pub_buf := new(bytes.Buffer)
	pub := &priv.PublicKey
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		err = fmt.Errorf("MarshalPKIXPublicKey: %v", err)
		return

	}
	pem.Encode(pub_buf, &pem.Block{Type: "EC PUBLIC KEY", Bytes: pubBytes})
	publicKey = pub_buf.Bytes()

	return
}

// SSHPublicKey return ssh.PublicKey from PEM encoded private key
func SSHPublicKey(privkey []byte) (pubkey ssh.PublicKey, err error) {
	priv, err := ssh.ParsePrivateKey(privkey)
	if err != nil {
		err = fmt.Errorf("ParsePrivateKey: %v", err)
		return
	}
	pubkey = priv.PublicKey()

	return
}

// SignECDSA sign a message with ECDSA private key
func SignECDSA(message []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}
	// encode signature to ASN1 format
	var sig struct {
		R, S *big.Int
	}
	sig.R, sig.S = r, s
	return asn1.Marshal(sig)
}

// SignWithCAKey signs the given data using the CA's private key
func SignWithCAKey(data []byte) ([]byte, error) {
	// Read the CA private key from the file
	caKeyData, err := os.ReadFile(CA_KEY_FILE)
	if err != nil {
		return nil, fmt.Errorf("read %s: %v", CA_KEY_FILE, err)
	}

	// Decode the PEM-encoded CA private key
	block, _ := pem.Decode(caKeyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse CA key PEM")
	}

	// Parse the ECDSA private key
	caPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %v", err)
	}

	// Hash the input data
	hash := sha256.Sum256(data)

	// Sign the hash using ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, caPrivateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	// Encode the signature in ASN.1 format
	var signature struct {
		R, S *big.Int
	}
	signature.R = r
	signature.S = s

	return asn1.Marshal(signature)
}

// VerifySignatureWithCA verifies the given signature against the data using the CA's public key
func VerifySignatureWithCA(data []byte, signature []byte) (bool, error) {
	// Read the CA certificate from the file
	caCertData, err := os.ReadFile(CA_CERT_FILE)
	if err != nil {
		return false, fmt.Errorf("read %s: %v", CA_CERT_FILE, err)
	}

	// Decode the PEM-encoded CA certificate
	block, _ := pem.Decode(caCertData)
	if block == nil {
		return false, fmt.Errorf("failed to parse CA cert PEM")
	}

	// Parse the X.509 certificate
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Extract the public key from the certificate (ECDSA public key)
	caPublicKey, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not ECDSA")
	}

	// Hash the input data
	hash := sha256.Sum256(data)

	// Decode the signature from ASN.1 format
	var sig struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(signature, &sig)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal signature: %v", err)
	}

	// Verify the signature using ECDSA
	isValid := ecdsa.Verify(caPublicKey, hash[:], sig.R, sig.S)
	return isValid, nil
}
