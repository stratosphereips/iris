package cryptotools

import (
	"testing"

	"github.com/golang/protobuf/proto"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"happystoic/p2pnetwork/pkg/messaging/pb"
)

// signMessage signs message with priv and fills in metadata.OriginalSender/Signature,
// mirroring what SignProtoMessage + the message construction call sites do.
func signMessage(t *testing.T, priv libp2pcrypto.PrivKey, nodeId peer.ID, message proto.Message, metadata *pb.MetaData) {
	t.Helper()
	pubMarshalled, err := libp2pcrypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		t.Fatalf("failed to marshal pubkey: %s", err)
	}
	metadata.OriginalSender = &pb.PeerIdentity{
		NodeId:     nodeId.String(),
		NodePubKey: pubMarshalled,
	}

	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatalf("failed to marshal message: %s", err)
	}
	sig, err := priv.Sign(data)
	if err != nil {
		t.Fatalf("failed to sign message: %s", err)
	}
	metadata.Signature = sig
}

func TestAuthenticateMessageAcceptsValidMessage(t *testing.T) {
	priv, pub, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}
	nodeId, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to derive peer id: %s", err)
	}

	metadata := &pb.MetaData{Id: "req-1"}
	msg := &pb.SingleEntityResponse{Metadata: metadata, Payload: []byte("intel data")}
	signMessage(t, priv, nodeId, msg, metadata)

	ck := &CryptoKit{}
	if err := ck.AuthenticateMessage(msg, metadata); err != nil {
		t.Fatalf("expected valid message to authenticate, got error: %s", err)
	}
}

// TestAuthenticateMessageRejectsNodeIdPubKeyMismatch is a regression test: an attacker
// can craft a message whose OriginalSender.NodeId does not correspond to the embedded
// NodePubKey (e.g. claiming to be a trusted peer while signing with their own key).
// AuthenticateMessage must reject this instead of silently returning nil (success).
func TestAuthenticateMessageRejectsNodeIdPubKeyMismatch(t *testing.T) {
	attackerPriv, _, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("failed to generate attacker key: %s", err)
	}
	_, victimPub, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("failed to generate victim key: %s", err)
	}
	victimId, err := peer.IDFromPublicKey(victimPub)
	if err != nil {
		t.Fatalf("failed to derive victim peer id: %s", err)
	}

	metadata := &pb.MetaData{Id: "req-1"}
	msg := &pb.SingleEntityResponse{Metadata: metadata, Payload: []byte("intel data")}
	// sign with the attacker's key, but claim the victim's node id
	signMessage(t, attackerPriv, victimId, msg, metadata)

	ck := &CryptoKit{}
	if err := ck.AuthenticateMessage(msg, metadata); err == nil {
		t.Fatal("expected authentication to fail for a node id / public key mismatch, got nil error")
	}
}

func TestAuthenticateMessageRejectsTamperedSignature(t *testing.T) {
	priv, pub, err := libp2pcrypto.GenerateKeyPair(libp2pcrypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}
	nodeId, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to derive peer id: %s", err)
	}

	metadata := &pb.MetaData{Id: "req-1"}
	msg := &pb.SingleEntityResponse{Metadata: metadata, Payload: []byte("intel data")}
	signMessage(t, priv, nodeId, msg, metadata)
	msg.Payload = []byte("tampered data")

	ck := &CryptoKit{}
	if err := ck.AuthenticateMessage(msg, metadata); err == nil {
		t.Fatal("expected authentication to fail for a tampered message, got nil error")
	}
}
