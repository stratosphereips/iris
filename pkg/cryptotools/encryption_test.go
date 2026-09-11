package cryptotools

import (
	"bytes"
	"crypto/rand"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"golang.org/x/crypto/nacl/box"
)

// TestEd25519ToCurve25519RoundTrip verifies that the Ed25519->X25519 key conversion used by
// EncryptForPeer/Decrypt actually produces a usable ECDH keypair on both sides: a message
// sealed with (recipient's converted public key, sender's converted private key) must open
// with (sender's converted public key, recipient's converted private key).
func TestEd25519ToCurve25519RoundTrip(t *testing.T) {
	senderPriv, senderPub, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("failed to generate sender key: %s", err)
	}
	recipientPriv, recipientPub, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("failed to generate recipient key: %s", err)
	}

	senderPubMarshalled, err := libp2pcrypto.MarshalPublicKey(senderPub)
	if err != nil {
		t.Fatalf("failed to marshal sender pubkey: %s", err)
	}
	recipientPubMarshalled, err := libp2pcrypto.MarshalPublicKey(recipientPub)
	if err != nil {
		t.Fatalf("failed to marshal recipient pubkey: %s", err)
	}

	senderCurvePriv, err := ed25519PrivKeyToCurve25519(senderPriv)
	if err != nil {
		t.Fatalf("failed to convert sender private key: %s", err)
	}
	recipientCurvePub, err := ed25519PubKeyToCurve25519(recipientPubMarshalled)
	if err != nil {
		t.Fatalf("failed to convert recipient public key: %s", err)
	}

	recipientCurvePriv, err := ed25519PrivKeyToCurve25519(recipientPriv)
	if err != nil {
		t.Fatalf("failed to convert recipient private key: %s", err)
	}
	senderCurvePub, err := ed25519PubKeyToCurve25519(senderPubMarshalled)
	if err != nil {
		t.Fatalf("failed to convert sender public key: %s", err)
	}

	plaintext := []byte("this is a secret threat intelligence payload")
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("failed to generate nonce: %s", err)
	}

	ciphertext := box.Seal(nil, plaintext, &nonce, recipientCurvePub, senderCurvePriv)
	opened, ok := box.Open(nil, ciphertext, &nonce, senderCurvePub, recipientCurvePriv)
	if !ok {
		t.Fatal("box.Open failed to authenticate/decrypt the message")
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %q, want %q", opened, plaintext)
	}

	// A third party's key must not be able to decrypt it.
	eavesdropperPriv, _, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("failed to generate eavesdropper key: %s", err)
	}
	eavesdropperCurvePriv, err := ed25519PrivKeyToCurve25519(eavesdropperPriv)
	if err != nil {
		t.Fatalf("failed to convert eavesdropper private key: %s", err)
	}
	if _, ok := box.Open(nil, ciphertext, &nonce, senderCurvePub, eavesdropperCurvePriv); ok {
		t.Fatal("eavesdropper was able to decrypt the message")
	}
}

func TestEd25519PubKeyToCurve25519RejectsNonEd25519(t *testing.T) {
	_, pub, err := libp2pcrypto.GenerateRSAKeyPair(2048, rand.Reader)
	if err != nil {
		t.Skipf("skipping, could not generate RSA key: %s", err)
	}
	marshalled, err := libp2pcrypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to marshal RSA pubkey: %s", err)
	}
	if _, err := ed25519PubKeyToCurve25519(marshalled); err == nil {
		t.Fatal("expected error converting non-Ed25519 public key, got nil")
	}
}
