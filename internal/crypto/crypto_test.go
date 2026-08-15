package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	master, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	k, err := NewKeyring(master)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := testKeyring(t)
	plaintext := []byte("-----BEGIN PRIVATE KEY-----\nnot really a key\n-----END PRIVATE KEY-----")

	env, err := k.Seal(plaintext, "")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(env.Ciphertext, plaintext) {
		t.Fatal("ciphertext contains the plaintext")
	}
	if len(env.Nonce) != nonceSize || len(env.Salt) != saltSize {
		t.Fatalf("nonce/salt sizes: %d/%d", len(env.Nonce), len(env.Salt))
	}

	got, err := k.Open(env, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("round-tripped plaintext does not match")
	}
}

func TestSealIsNonDeterministic(t *testing.T) {
	k := testKeyring(t)
	plaintext := []byte("same input")

	a, err := k.Seal(plaintext, "")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := k.Seal(plaintext, "")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Error("sealing the same plaintext twice produced identical ciphertext")
	}
	if bytes.Equal(a.Nonce, b.Nonce) {
		t.Error("nonce was reused across two seals")
	}
}

func TestPassphraseIsRequiredToOpen(t *testing.T) {
	k := testKeyring(t)
	plaintext := []byte("ca private key")

	env, err := k.Seal(plaintext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// The master key alone must not be enough.
	if _, err := k.Open(env, ""); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("opening without the passphrase: got %v, want ErrPassphraseRequired", err)
	}
	if _, err := k.Open(env, "wrong passphrase"); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("opening with the wrong passphrase: got %v, want ErrPassphraseRequired", err)
	}

	got, err := k.Open(env, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Open with the right passphrase: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("plaintext does not match")
	}
}

func TestOpenWithADifferentMasterKeyFails(t *testing.T) {
	a := testKeyring(t)
	b := testKeyring(t)

	env, err := a.Seal([]byte("secret"), "")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := b.Open(env, ""); err == nil {
		t.Error("a different master key opened the envelope")
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	k := testKeyring(t)
	env, err := k.Seal([]byte("authenticated data"), "")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	env.Ciphertext[0] ^= 0xFF
	if _, err := k.Open(env, ""); err == nil {
		t.Error("GCM accepted tampered ciphertext")
	}
}

func TestNewKeyringRejectsWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := NewKeyring(make([]byte, size)); err == nil {
			t.Errorf("NewKeyring accepted a %d-byte key", size)
		}
	}
}

func TestParseMasterKeyFormats(t *testing.T) {
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}

	// Hex, as FormatMasterKey emits.
	parsed, err := ParseMasterKey(FormatMasterKey(key))
	if err != nil {
		t.Fatalf("ParseMasterKey(hex): %v", err)
	}
	if !bytes.Equal(parsed, key) {
		t.Error("hex round-trip failed")
	}

	// Base64.
	parsed, err = ParseMasterKey("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if err != nil {
		t.Fatalf("ParseMasterKey(base64): %v", err)
	}
	if len(parsed) != MasterKeySize {
		t.Errorf("base64 key is %d bytes", len(parsed))
	}

	// 32 raw characters.
	parsed, err = ParseMasterKey("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("ParseMasterKey(raw): %v", err)
	}
	if len(parsed) != MasterKeySize {
		t.Errorf("raw key is %d bytes", len(parsed))
	}

	for _, bad := range []string{"", "short", "not-32-bytes-and-not-valid-hex!!!!!!"} {
		if _, err := ParseMasterKey(bad); err == nil {
			t.Errorf("ParseMasterKey(%q) should have failed", bad)
		}
	}
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("s3cr3t-passphrase")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if len(hash) < 50 || hash[:9] != "$argon2id" {
		t.Fatalf("hash is not in PHC argon2id form: %q", hash)
	}

	if err := VerifyPassword("s3cr3t-passphrase", hash); err != nil {
		t.Errorf("VerifyPassword with the right password: %v", err)
	}
	if err := VerifyPassword("wrong", hash); !errors.Is(err, ErrMismatchedPassword) {
		t.Errorf("VerifyPassword with the wrong password: got %v, want ErrMismatchedPassword", err)
	}

	// Two hashes of the same password must differ (unique salts).
	other, err := HashPassword("s3cr3t-passphrase")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if other == hash {
		t.Error("the same password produced identical hashes — the salt is not random")
	}

	for _, bad := range []string{"", "not-a-hash", "$argon2i$v=19$m=1,t=1,p=1$aaaa$bbbb"} {
		if err := VerifyPassword("x", bad); !errors.Is(err, ErrInvalidHash) && err == nil {
			t.Errorf("VerifyPassword against %q should have failed", bad)
		}
	}
	if _, err := HashPassword(""); err == nil {
		t.Error("hashing an empty password should fail")
	}
}

func TestAPITokenGeneration(t *testing.T) {
	token, hash, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	if len(token) < 40 || token[:7] != "certio_" {
		t.Errorf("token %q is not in the expected form", token)
	}
	if HashAPIToken(token) != hash {
		t.Error("HashAPIToken does not reproduce the stored hash")
	}
	if HashAPIToken(token+"x") == hash {
		t.Error("a different token produced the same hash")
	}

	// Tokens must be unique.
	seen := map[string]bool{}
	for range 100 {
		tok, _, err := GenerateAPIToken()
		if err != nil {
			t.Fatalf("GenerateAPIToken: %v", err)
		}
		if seen[tok] {
			t.Fatal("duplicate API token generated")
		}
		seen[tok] = true
	}
}
