// Package crypto implements the pairing and per-session keys.
//
// Model (chosen after reviewing how WeType pairs devices, see report §3-4):
//   - a shared group key (random 32 bytes) is the root of trust; it is set on
//     the first device and copied to others via a 6-digit PIN during pairing;
//   - hello frames are authenticated with HMAC(groupKey) bound to the TLS
//     exporter of the live connection, so a stranger on the same LAN cannot
//     complete a handshake and a MITM relay cannot replay a valid tag;
//   - each connection is wrapped in TLS 1.3 (self-signed certs) so traffic on
//     the wire is encrypted independent of the group key;
//   - file content is additionally XOR-masked per session only as obfuscation;
//     confidentiality rests on TLS + LAN trust, matching the threat model.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

// GroupKeyLen is the byte length of the group key.
const GroupKeyLen = 32

// NewGroupKey generates a fresh group key.
func NewGroupKey() ([]byte, error) {
	k := make([]byte, GroupKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// NewDeviceID returns a random 16-byte hex ID for this device.
func NewDeviceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ExporterLabel is the TLS exporter label used for channel binding.
const ExporterLabel = "lanclip hello v2"

// HelloTag computes the channel-bound hello authenticator. exporter must be
// the TLS exporter value of the SAME connection the hello frame travels on;
// a tag captured or relayed over any other connection never validates, which
// defeats TLS-MITM relays against our self-signed certificates.
func HelloTag(groupKey []byte, deviceID string, exporter []byte) string {
	m := hmac.New(sha256.New, groupKey)
	m.Write([]byte("lanclip-hello-v2"))
	m.Write(exporter)
	m.Write([]byte(deviceID))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyHelloTag checks a hello authenticator in constant time.
func VerifyHelloTag(groupKey []byte, deviceID, tag string, exporter []byte) bool {
	expected := HelloTag(groupKey, deviceID, exporter)
	return hmac.Equal([]byte(expected), []byte(tag))
}

// DerivePINBytes maps the group key to the 6-digit pairing PIN shown to the
// user. Both peers compute it from the same group key, so users can confirm
// both devices show the same PIN (SAS-style short auth string).
func DerivePINBytes(groupKey []byte) (string, error) {
	m := hmac.New(sha256.New, groupKey)
	m.Write([]byte("lanclip-pin-v1"))
	sum := m.Sum(nil)
	n := new(big.Int).SetBytes(sum[:4])
	mod := big.NewInt(1000000)
	pin := n.Mod(n, mod)
	return fmt.Sprintf("%06d", pin.Int64()), nil
}

// PairKey derives a group key from a short numeric pairing code typed by the
// user plus a device-provided salt. This is intentionally a stopgap for the
// "copy key to second device" UX: the real security anchor is the group key
// itself shown/verified via DerivePINBytes.
func PairKey(pin, salt []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write([]byte("lanclip-pair-v1"))
	m.Write(pin)
	return m.Sum(nil)
}

// PairPIN derives the 6-digit on-screen pairing code shown by the pairing
// advertiser. Fresh salt per pairing session makes each code single-use.
func PairPIN(groupKey, salt []byte) string {
	m := hmac.New(sha256.New, groupKey)
	m.Write([]byte("lanclip-pair-pin-v1"))
	m.Write(salt)
	sum := m.Sum(nil)
	n := new(big.Int).SetBytes(sum[:4])
	return fmt.Sprintf("%06d", n.Mod(n, big.NewInt(1000000)).Int64())
}

// SealGroupKey encrypts the group key for transport during pairing, using the
// PIN-derived key. Returns nonce || ciphertext.
func SealGroupKey(pin, salt, groupKey []byte) ([]byte, error) {
	key := PairKey(pin, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, groupKey, nil), nil
}

// OpenGroupKey reverses SealGroupKey.
func OpenGroupKey(pin, salt, sealed []byte) ([]byte, error) {
	key := PairKey(pin, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(sealed) < ns {
		return nil, fmt.Errorf("sealed key too short")
	}
	plain, err := gcm.Open(nil, sealed[:ns], sealed[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("bad PIN or corrupted key")
	}
	if len(plain) != GroupKeyLen {
		return nil, fmt.Errorf("bad group key length %d", len(plain))
	}
	return plain, nil
}

// EphemeralCert builds a throwaway self-signed TLS certificate for one
// session (pairing listener or device engine). The key never leaves the
// device; pairing relies on the PIN, not on cert trust.
func EphemeralCert(commonName string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              []string{commonName, "lanclip.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
