// Package acme implements the server side of RFC 8555 — the protocol
// cert-manager, Traefik, Caddy, certbot and acme.sh all speak.
//
// It is what turns Certio from a place someone goes to click "issue" into
// infrastructure: a workload points its existing ACME client at this
// directory and its internal certificates renew themselves, with no operator
// in the loop and nothing new to install.
//
// The JOSE handling here is deliberately a small hand-written subset rather
// than a general library. ACME uses exactly one serialisation (flattened JSON
// JWS), a closed set of signature algorithms, and no encryption at all — and a
// full JOSE implementation brings along the algorithm agility that has been
// the source of most JWT vulnerabilities. Nothing below will ever accept
// "none", or let a header choose which key verifies it.
package acme

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// b64 is the encoding every field in a JWS uses: URL-safe, unpadded.
var b64 = base64.RawURLEncoding

// Signature algorithms Certio accepts. Anything else is refused by name, so a
// client using an exotic one gets a clear error rather than a silent failure.
const (
	AlgRS256 = "RS256"
	AlgRS384 = "RS384"
	AlgRS512 = "RS512"
	AlgES256 = "ES256"
	AlgES384 = "ES384"
	AlgES512 = "ES512"
	AlgEdDSA = "EdDSA"
	AlgHS256 = "HS256"
)

// JWS is the flattened JSON serialisation ACME requires (RFC 8555 §6.2).
type JWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// ProtectedHeader is the subset of the JOSE header ACME defines.
type ProtectedHeader struct {
	Alg   string `json:"alg"`
	Nonce string `json:"nonce"`
	URL   string `json:"url"`
	// Exactly one of JWK and KID is present: a JWK for the requests that
	// introduce a key (new-account, revoke-cert with the certificate key), a
	// KID — the account URL — for everything afterwards.
	JWK *JWK   `json:"jwk,omitempty"`
	KID string `json:"kid,omitempty"`
}

// JWK is a public key in JSON form (RFC 7517), restricted to the key types
// ACME clients actually present.
type JWK struct {
	Kty string `json:"kty"`
	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// ParseJWS decodes the flattened serialisation and its protected header.
func ParseJWS(body []byte) (*JWS, *ProtectedHeader, []byte, error) {
	var jws JWS
	if err := json.Unmarshal(body, &jws); err != nil {
		return nil, nil, nil, fmt.Errorf("acme: not a flattened JWS: %w", err)
	}
	if jws.Protected == "" || jws.Signature == "" {
		return nil, nil, nil, errors.New("acme: the JWS is missing its protected header or signature")
	}

	protectedRaw, err := b64.DecodeString(jws.Protected)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("acme: decode the protected header: %w", err)
	}
	var header ProtectedHeader
	if err := json.Unmarshal(protectedRaw, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("acme: parse the protected header: %w", err)
	}

	// RFC 8555 §6.2: exactly one of jwk and kid. Accepting both would let a
	// request claim one account's identity while being verified by another
	// key, which is the whole game.
	if (header.JWK == nil) == (header.KID == "") {
		return nil, nil, nil, errors.New("acme: the protected header must carry exactly one of jwk and kid")
	}

	// An empty payload is POST-as-GET, which is a legitimate and common case:
	// every read in ACME is an authenticated POST with no body.
	payload, err := b64.DecodeString(jws.Payload)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("acme: decode the payload: %w", err)
	}
	return &jws, &header, payload, nil
}

// Verify checks the signature over the protected header and payload.
func (j *JWS) Verify(header *ProtectedHeader, key crypto.PublicKey) error {
	signature, err := b64.DecodeString(j.Signature)
	if err != nil {
		return fmt.Errorf("acme: decode the signature: %w", err)
	}
	signing := []byte(j.Protected + "." + j.Payload)

	hash, err := hashFor(header.Alg)
	if err != nil {
		return err
	}

	switch header.Alg {
	case AlgRS256, AlgRS384, AlgRS512:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("acme: %s needs an RSA key, got %T", header.Alg, key)
		}
		digest := digestOf(hash, signing)
		if err := rsa.VerifyPKCS1v15(pub, hash, digest, signature); err != nil {
			return errors.New("acme: the JWS signature does not verify")
		}
		return nil

	case AlgES256, AlgES384, AlgES512:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("acme: %s needs an ECDSA key, got %T", header.Alg, key)
		}
		// JOSE uses the fixed-width R‖S encoding, not the ASN.1 sequence
		// ecdsa.VerifyASN1 expects. The width is the curve's, so a signature
		// of the wrong length is rejected before any big.Int work.
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*size {
			return fmt.Errorf("acme: an %s signature must be %d bytes, got %d",
				header.Alg, 2*size, len(signature))
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(pub, digestOf(hash, signing), r, s) {
			return errors.New("acme: the JWS signature does not verify")
		}
		return nil

	case AlgEdDSA:
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("acme: EdDSA needs an Ed25519 key, got %T", key)
		}
		if !ed25519.Verify(pub, signing, signature) {
			return errors.New("acme: the JWS signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("acme: unsupported signature algorithm %q", header.Alg)
}

// VerifyHMAC checks a signature made with a shared secret, which is how
// external account binding proves the client holds the key an administrator
// issued out of band.
func (j *JWS) VerifyHMAC(alg string, secret []byte) error {
	if alg != AlgHS256 {
		return fmt.Errorf("acme: external account binding must use HS256, not %q", alg)
	}
	signature, err := b64.DecodeString(j.Signature)
	if err != nil {
		return fmt.Errorf("acme: decode the signature: %w", err)
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(j.Protected + "." + j.Payload))
	if !hmac.Equal(mac.Sum(nil), signature) {
		return errors.New("acme: the external account binding does not verify")
	}
	return nil
}

func hashFor(alg string) (crypto.Hash, error) {
	switch alg {
	case AlgRS256, AlgES256, AlgHS256:
		return crypto.SHA256, nil
	case AlgRS384, AlgES384:
		return crypto.SHA384, nil
	case AlgRS512, AlgES512:
		return crypto.SHA512, nil
	case AlgEdDSA:
		// Ed25519 hashes internally; the caller signs the message itself.
		return 0, nil
	}
	return 0, fmt.Errorf("acme: unsupported signature algorithm %q", alg)
}

func digestOf(hash crypto.Hash, data []byte) []byte {
	switch hash {
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:]
	default:
		sum := sha256.Sum256(data)
		return sum[:]
	}
}

// PublicKey converts a JWK into a crypto.PublicKey.
func (k *JWK) PublicKey() (crypto.PublicKey, error) {
	if k == nil {
		return nil, errors.New("acme: no key was supplied")
	}

	switch k.Kty {
	case "EC":
		curve, ecdhCurve, size, err := curveFor(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("acme: decode the key's x coordinate: %w", err)
		}
		y, err := b64.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("acme: decode the key's y coordinate: %w", err)
		}
		// RFC 7518 §6.2.1.2 fixes the coordinate width, and a short one would
		// otherwise be silently left-padded into a different point.
		if len(x) != size || len(y) != size {
			return nil, fmt.Errorf("acme: %s coordinates must be %d bytes each", k.Crv, size)
		}

		// The on-curve check goes through crypto/ecdh rather than the
		// deprecated elliptic.IsOnCurve: NewPublicKey validates the point, and
		// an unchecked point reaching crypto/ecdsa is a well-known way to leak
		// information about a private key in other protocols.
		point := make([]byte, 0, 1+2*size)
		point = append(point, 4) // SEC 1 uncompressed
		point = append(point, x...)
		point = append(point, y...)
		if _, err := ecdhCurve.NewPublicKey(point); err != nil {
			return nil, fmt.Errorf("acme: the supplied point is not on the curve: %w", err)
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil

	case "RSA":
		n, err := b64.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("acme: decode the key's modulus: %w", err)
		}
		e, err := b64.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("acme: decode the key's exponent: %w", err)
		}
		if len(n) < 256 {
			return nil, errors.New("acme: an RSA account key must be at least 2048 bits")
		}
		exponent := new(big.Int).SetBytes(e)
		if !exponent.IsInt64() || exponent.Int64() < 3 {
			return nil, errors.New("acme: the RSA public exponent is out of range")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent.Int64())}, nil

	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("acme: unsupported OKP curve %q", k.Crv)
		}
		x, err := b64.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("acme: decode the key: %w", err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("acme: an Ed25519 key must be 32 bytes")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("acme: unsupported key type %q", k.Kty)
}

// curveFor returns both spellings of a curve: the elliptic.Curve that
// crypto/ecdsa still wants, and the ecdh.Curve whose NewPublicKey does the
// on-curve validation.
func curveFor(name string) (curve elliptic.Curve, exchange ecdh.Curve, size int, err error) {
	switch name {
	case "P-256":
		return elliptic.P256(), ecdh.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), ecdh.P384(), 48, nil
	case "P-521":
		return elliptic.P521(), ecdh.P521(), 66, nil
	}
	return nil, nil, 0, fmt.Errorf("acme: unsupported curve %q", name)
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint, base64url-encoded.
//
// It is the account's stable identity: the key authorization a challenge is
// validated against is "<token>.<thumbprint>", which is what ties a DNS record
// or an HTTP file to the specific account that asked for the certificate
// rather than to anyone who observed the token.
func (k *JWK) Thumbprint() (string, error) {
	var canonical string
	switch k.Kty {
	case "EC":
		// The member order is not a style choice: RFC 7638 requires the
		// lexicographic order of the required members, with no whitespace.
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
	case "RSA":
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
	case "OKP":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, k.Crv, k.X)
	default:
		return "", fmt.Errorf("acme: cannot thumbprint key type %q", k.Kty)
	}

	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:]), nil
}

// KeyAuthorization is the value a challenge is proved with (RFC 8555 §8.1).
func KeyAuthorization(token string, key *JWK) (string, error) {
	thumbprint, err := key.Thumbprint()
	if err != nil {
		return "", err
	}
	return token + "." + thumbprint, nil
}

// DNSRecordValue is what a dns-01 TXT record must contain: the base64url
// SHA-256 of the key authorization, not the authorization itself.
func DNSRecordValue(keyAuthorization string) string {
	sum := sha256.Sum256([]byte(keyAuthorization))
	return b64.EncodeToString(sum[:])
}

// Encode renders a JWK as JSON for storage, so an account key can be compared
// byte for byte on a later request.
func (k *JWK) Encode() (string, error) {
	raw, err := json.Marshal(k)
	if err != nil {
		return "", fmt.Errorf("acme: encode the account key: %w", err)
	}
	return string(raw), nil
}

// DecodeJWK reads a stored key back.
func DecodeJWK(encoded string) (*JWK, error) {
	var key JWK
	if err := json.Unmarshal([]byte(encoded), &key); err != nil {
		return nil, fmt.Errorf("acme: parse the stored account key: %w", err)
	}
	return &key, nil
}

// Base64URL exposes the encoding for callers that need to build a token.
func Base64URL(data []byte) string { return b64.EncodeToString(data) }
