package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// signES256 builds a flattened JWS the way a client would, so the tests
// exercise the same shape the server actually receives.
func signES256(t *testing.T, key *ecdsa.PrivateKey, header ProtectedHeader, payload []byte) *JWS {
	t.Helper()
	header.Alg = AlgES256

	protectedRaw, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	protected := b64.EncodeToString(protectedRaw)
	encodedPayload := b64.EncodeToString(payload)

	digest := sha256.Sum256([]byte(protected + "." + encodedPayload))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// JOSE wants fixed-width R‖S, left-padded — not the ASN.1 sequence
	// ecdsa.SignASN1 produces.
	size := 32
	signature := make([]byte, 2*size)
	r.FillBytes(signature[:size])
	s.FillBytes(signature[size:])

	return &JWS{
		Protected: protected,
		Payload:   encodedPayload,
		Signature: b64.EncodeToString(signature),
	}
}

func testECKey(t *testing.T) (*ecdsa.PrivateKey, *JWK) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)

	return key, &JWK{
		Kty: "EC", Crv: "P-256",
		X: b64.EncodeToString(x), Y: b64.EncodeToString(y),
	}
}

// TestVerifyES256 is the happy path every ACME request takes.
func TestVerifyES256(t *testing.T) {
	key, jwk := testECKey(t)
	header := ProtectedHeader{Nonce: "n1", URL: "https://ca.example.com/acme/new-order", JWK: jwk}
	jws := signES256(t, key, header, []byte(`{"identifiers":[]}`))

	raw, err := json.Marshal(jws)
	if err != nil {
		t.Fatalf("marshal jws: %v", err)
	}

	parsed, parsedHeader, payload, err := ParseJWS(raw)
	if err != nil {
		t.Fatalf("ParseJWS: %v", err)
	}
	if parsedHeader.Nonce != "n1" || parsedHeader.URL != header.URL {
		t.Errorf("header = %+v", parsedHeader)
	}
	if string(payload) != `{"identifiers":[]}` {
		t.Errorf("payload = %s", payload)
	}

	pub, err := parsedHeader.JWK.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if err := parsed.Verify(parsedHeader, pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TestVerifyRejectsATamperedPayload is the property the whole protocol rests
// on: the signature covers the payload, so changing it must break.
func TestVerifyRejectsATamperedPayload(t *testing.T) {
	key, jwk := testECKey(t)
	jws := signES256(t, key,
		ProtectedHeader{Nonce: "n1", URL: "https://ca.example.com/acme/new-order", JWK: jwk},
		[]byte(`{"identifiers":["a.example.com"]}`))

	// Swap in a different set of names, exactly as an attacker would.
	jws.Payload = b64.EncodeToString([]byte(`{"identifiers":["evil.example.com"]}`))

	raw, _ := json.Marshal(jws)
	parsed, header, _, err := ParseJWS(raw)
	if err != nil {
		t.Fatalf("ParseJWS: %v", err)
	}
	pub, _ := header.JWK.PublicKey()
	if err := parsed.Verify(header, pub); err == nil {
		t.Fatal("a tampered payload verified")
	}
}

// TestVerifyRejectsTheWrongKey checks that a valid signature from some other
// key is not accepted.
func TestVerifyRejectsTheWrongKey(t *testing.T) {
	key, jwk := testECKey(t)
	_, otherJWK := testECKey(t)

	jws := signES256(t, key,
		ProtectedHeader{Nonce: "n1", URL: "https://ca.example.com/x", JWK: jwk}, []byte("{}"))
	raw, _ := json.Marshal(jws)
	parsed, header, _, _ := ParseJWS(raw)

	otherPub, _ := otherJWK.PublicKey()
	if err := parsed.Verify(header, otherPub); err == nil {
		t.Fatal("a signature verified under an unrelated key")
	}
}

// TestParseJWSRequiresExactlyOneKeyReference is RFC 8555 §6.2. Accepting both
// would let a request claim one account's identity while being verified by
// another key.
func TestParseJWSRequiresExactlyOneKeyReference(t *testing.T) {
	_, jwk := testECKey(t)

	both, _ := json.Marshal(ProtectedHeader{
		Alg: AlgES256, Nonce: "n", URL: "u", JWK: jwk, KID: "https://ca/acme/account/1",
	})
	neither, _ := json.Marshal(ProtectedHeader{Alg: AlgES256, Nonce: "n", URL: "u"})

	for name, header := range map[string][]byte{"both": both, "neither": neither} {
		raw, _ := json.Marshal(JWS{
			Protected: b64.EncodeToString(header),
			Payload:   b64.EncodeToString([]byte("{}")),
			Signature: b64.EncodeToString([]byte("sig")),
		})
		if _, _, _, err := ParseJWS(raw); err == nil {
			t.Errorf("ParseJWS accepted a header with %s jwk and kid", name)
		}
	}
}

// TestVerifyRejectsAnUnsupportedAlgorithm makes sure "none" and friends have
// no path through, which is the failure mode most JWT libraries are famous for.
func TestVerifyRejectsAnUnsupportedAlgorithm(t *testing.T) {
	key, jwk := testECKey(t)
	jws := signES256(t, key, ProtectedHeader{Nonce: "n", URL: "u", JWK: jwk}, []byte("{}"))

	pub, _ := jwk.PublicKey()
	for _, alg := range []string{"none", "", "HS256", "ES256K"} {
		header := &ProtectedHeader{Alg: alg, JWK: jwk}
		if err := jws.Verify(header, pub); err == nil {
			t.Errorf("Verify accepted alg %q", alg)
		}
	}
}

// TestVerifyRejectsAMisSizedECDSASignature covers the raw R‖S width check. A
// short signature left-padded into a big.Int would be a different signature.
func TestVerifyRejectsAMisSizedECDSASignature(t *testing.T) {
	key, jwk := testECKey(t)
	jws := signES256(t, key, ProtectedHeader{Nonce: "n", URL: "u", JWK: jwk}, []byte("{}"))
	jws.Signature = b64.EncodeToString([]byte("short"))

	pub, _ := jwk.PublicKey()
	err := jws.Verify(&ProtectedHeader{Alg: AlgES256, JWK: jwk}, pub)
	if err == nil {
		t.Fatal("a mis-sized signature verified")
	}
	if !strings.Contains(err.Error(), "64 bytes") {
		t.Errorf("error = %v, want it to name the expected width", err)
	}
}

// TestThumbprintMatchesRFC7638 uses the worked example from the RFC, which is
// the only way to know the canonical form is right. Getting this wrong would
// make every challenge fail in a way that looks like a client bug.
func TestThumbprintMatchesRFC7638(t *testing.T) {
	// RFC 7638 §3.1's example key, and the thumbprint it prints in §3.1.
	key := &JWK{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
	}
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	got, err := key.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if got != want {
		t.Errorf("Thumbprint = %q, want %q", got, want)
	}
}

// TestKeyAuthorization checks the value a challenge is proved with, and the
// digest a dns-01 TXT record has to carry.
func TestKeyAuthorization(t *testing.T) {
	_, jwk := testECKey(t)
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}

	auth, err := KeyAuthorization("tok3n", jwk)
	if err != nil {
		t.Fatalf("KeyAuthorization: %v", err)
	}
	if want := "tok3n." + thumbprint; auth != want {
		t.Errorf("KeyAuthorization = %q, want %q", auth, want)
	}

	sum := sha256.Sum256([]byte(auth))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); DNSRecordValue(auth) != want {
		t.Errorf("DNSRecordValue = %q, want %q", DNSRecordValue(auth), want)
	}
}

// TestPublicKeyRejectsBadKeys covers the guards on untrusted key material.
func TestPublicKeyRejectsBadKeys(t *testing.T) {
	cases := map[string]*JWK{
		"unknown key type":     {Kty: "oct", X: "AAAA"},
		"unsupported curve":    {Kty: "EC", Crv: "P-192", X: "AAAA", Y: "AAAA"},
		"short EC coordinates": {Kty: "EC", Crv: "P-256", X: "AAAA", Y: "AAAA"},
		"undersized RSA":       {Kty: "RSA", N: b64.EncodeToString(make([]byte, 128)), E: "AQAB"},
		"bad Ed25519 length":   {Kty: "OKP", Crv: "Ed25519", X: "AAAA"},
	}
	for name, key := range cases {
		if _, err := key.PublicKey(); err == nil {
			t.Errorf("PublicKey accepted a key with %s", name)
		}
	}
}

// TestPublicKeyRejectsAPointOffTheCurve is the check that keeps an invalid
// curve point from reaching crypto/ecdsa.
func TestPublicKeyRejectsAPointOffTheCurve(t *testing.T) {
	_, jwk := testECKey(t)

	// Flip the x coordinate to something that is almost certainly not on the
	// curve, keeping the width valid so the length check passes.
	bad := make([]byte, 32)
	bad[31] = 2
	jwk.X = b64.EncodeToString(bad)

	if _, err := jwk.PublicKey(); err == nil {
		t.Fatal("PublicKey accepted a point off the curve")
	}
}

// TestVerifyHMAC covers the external account binding path.
func TestVerifyHMAC(t *testing.T) {
	secret := []byte("shared-secret-bytes")
	protected := b64.EncodeToString([]byte(`{"alg":"HS256","kid":"abc","url":"https://ca/acme/new-account"}`))
	payload := b64.EncodeToString([]byte(`{"kty":"EC"}`))

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(protected + "." + payload))

	jws := &JWS{Protected: protected, Payload: payload, Signature: b64.EncodeToString(mac.Sum(nil))}
	if err := jws.VerifyHMAC(AlgHS256, secret); err != nil {
		t.Errorf("VerifyHMAC: %v", err)
	}
	if err := jws.VerifyHMAC(AlgHS256, []byte("wrong")); err == nil {
		t.Error("VerifyHMAC accepted the wrong secret")
	}
	// Only HS256: allowing an asymmetric alg here would let a client supply
	// the verifying key alongside the signature.
	if err := jws.VerifyHMAC(AlgES256, secret); err == nil {
		t.Error("VerifyHMAC accepted a non-HMAC algorithm")
	}
}

// TestRSAKeyRoundTrip checks the other key type clients commonly use.
func TestRSAKeyRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := &JWK{
		Kty: "RSA",
		N:   b64.EncodeToString(key.N.Bytes()),
		E:   b64.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}

	pub, err := jwk.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	parsed, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey returned %T", pub)
	}
	if parsed.N.Cmp(key.N) != 0 || parsed.E != key.E {
		t.Error("the RSA key did not survive the round trip")
	}
}

// TestEncodeDecodeJWK checks the storage round trip an account key takes.
func TestEncodeDecodeJWK(t *testing.T) {
	_, jwk := testECKey(t)

	encoded, err := jwk.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeJWK(encoded)
	if err != nil {
		t.Fatalf("DecodeJWK: %v", err)
	}

	before, _ := jwk.Thumbprint()
	after, _ := decoded.Thumbprint()
	if before != after {
		t.Error("the thumbprint changed across a storage round trip")
	}
}
