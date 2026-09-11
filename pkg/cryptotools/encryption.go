package cryptotools

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"

	"filippo.io/edwards25519"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/box"
)

// EncryptedEnvelope is the wire format of an asymmetrically encrypted p2p payload.
// SenderPubKey (libp2p-marshalled Ed25519 public key) travels alongside the ciphertext
// so the recipient can derive the shared secret needed to decrypt it, since the message
// may be relayed through intermediate peers that must not be able to read its contents.
type EncryptedEnvelope struct {
	SenderPubKey []byte `json:"senderPubKey"`
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
}

// EncryptForPeer encrypts plaintext with a key derived from this node's private key and
// recipientPubKey (a libp2p-marshalled Ed25519 public key), so that only the holder of the
// matching private key can decrypt it.
func (ck *CryptoKit) EncryptForPeer(recipientPubKey []byte, plaintext []byte) ([]byte, error) {
	recipientCurveKey, err := ed25519PubKeyToCurve25519(recipientPubKey)
	if err != nil {
		return nil, errors.WithMessage(err, "error converting recipient public key")
	}

	ownPriv := ck.host.Peerstore().PrivKey(ck.host.ID())
	ownCurvePriv, err := ed25519PrivKeyToCurve25519(ownPriv)
	if err != nil {
		return nil, errors.WithMessage(err, "error converting own private key")
	}
	ownPubMarshalled, err := libp2pcrypto.MarshalPublicKey(ownPriv.GetPublic())
	if err != nil {
		return nil, errors.WithMessage(err, "error marshalling own public key")
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.WithMessage(err, "error generating nonce")
	}

	ciphertext := box.Seal(nil, plaintext, &nonce, recipientCurveKey, ownCurvePriv)

	return json.Marshal(&EncryptedEnvelope{
		SenderPubKey: ownPubMarshalled,
		Nonce:        nonce[:],
		Ciphertext:   ciphertext,
	})
}

// Decrypt decrypts data previously produced by EncryptForPeer using this node's own
// private key together with the sender's public key embedded in the envelope.
func (ck *CryptoKit) Decrypt(data []byte) ([]byte, error) {
	env := &EncryptedEnvelope{}
	if err := json.Unmarshal(data, env); err != nil {
		return nil, errors.WithMessage(err, "error unmarshalling encrypted envelope")
	}
	if len(env.Nonce) != 24 {
		return nil, errors.New("invalid nonce length in encrypted envelope")
	}

	senderCurveKey, err := ed25519PubKeyToCurve25519(env.SenderPubKey)
	if err != nil {
		return nil, errors.WithMessage(err, "error converting sender public key")
	}
	ownPriv := ck.host.Peerstore().PrivKey(ck.host.ID())
	ownCurvePriv, err := ed25519PrivKeyToCurve25519(ownPriv)
	if err != nil {
		return nil, errors.WithMessage(err, "error converting own private key")
	}

	var nonce [24]byte
	copy(nonce[:], env.Nonce)

	plaintext, ok := box.Open(nil, env.Ciphertext, &nonce, senderCurveKey, ownCurvePriv)
	if !ok {
		return nil, errors.New("error decrypting envelope: authentication failed")
	}
	return plaintext, nil
}

// ed25519PubKeyToCurve25519 converts a libp2p-marshalled Ed25519 public key into its
// birationally-equivalent Curve25519 (X25519) public key, usable for ECDH.
func ed25519PubKeyToCurve25519(marshalled []byte) (*[32]byte, error) {
	key, err := libp2pcrypto.UnmarshalPublicKey(marshalled)
	if err != nil {
		return nil, err
	}
	if key.Type() != pb.KeyType_Ed25519 {
		return nil, errors.New("public key is not an Ed25519 key")
	}
	raw, err := key.Raw()
	if err != nil {
		return nil, err
	}

	point, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid ed25519 public key")
	}
	var out [32]byte
	copy(out[:], point.BytesMontgomery())
	return &out, nil
}

// ed25519PrivKeyToCurve25519 derives the Curve25519 (X25519) private scalar corresponding
// to an Ed25519 private key, following the standard Ed25519->X25519 conversion (as used by
// e.g. age and libsodium's crypto_sign_ed25519_sk_to_curve25519).
func ed25519PrivKeyToCurve25519(priv libp2pcrypto.PrivKey) (*[32]byte, error) {
	if priv.Type() != pb.KeyType_Ed25519 {
		return nil, errors.New("private key is not an Ed25519 key")
	}
	raw, err := priv.Raw()
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("unexpected ed25519 private key size")
	}

	digest := sha512.Sum512(ed25519.PrivateKey(raw).Seed())
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var out [32]byte
	copy(out[:], digest[:32])
	return &out, nil
}
