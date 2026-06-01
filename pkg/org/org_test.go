package org

import (
	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	_ "github.com/pkg/errors"
	"testing"
)

func TestOrgString(t *testing.T) {
	tests := []struct {
		name string
		org  Org
		want string
	}{
		{
			name: "Test Org String representation",
			org:  Org(peer.ID("QmTestPeerID")),
			want: "2Y87tYwhjroXf5GVH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.org.String()
			if got != tt.want {
				t.Errorf("Org.String() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestOrgCid(t *testing.T) {
	tests := []struct {
		name string
		org  Org
		want string
	}{
		{
			name: "Test Org Cid conversion",
			org:  Org(peer.ID("peer1")),
			want: "QmVSbC2t7EN59erRtZ2MkD73C6N5HJ5xq5ieZc1mzmyfCt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.org.Cid()
			if err != nil {
				t.Errorf("Org.Cid() error = %v", err)
				return
			}

			// Decode expected CID string to cid.Cid type
			wantCid, err := cid.Decode(tt.want)
			if err != nil {
				t.Fatalf("Failed to decode expected CID: %v", err)
			}

			// Compare generated CID with expected CID
			if !got.Equals(wantCid) {
				t.Errorf("Org.Cid() = %v; want %v", got, wantCid)
			}
		})
	}
}

func TestVerifyPeer(t *testing.T) {
	tests := []struct {
		name    string
		org     Org
		peerID  peer.ID
		b64Sig  string
		want    bool
		wantErr bool
	}{
		{
			name:    "Invalid signature verification",
			org:     Org(peer.ID("QmTestOrg")),
			peerID:  peer.ID("QmTestPeerID"),
			b64Sig:  "invalidBase64Signature",
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.org.VerifyPeer(tt.peerID, tt.b64Sig)
			if (err != nil) != tt.wantErr {
				t.Errorf("Org.VerifyPeer() error = %v; wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Org.VerifyPeer() = %v; want %v", got, tt.want)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "Valid Org ID",
			input:   "QmVSbC2t7EN59erRtZ2MkD73C6N5HJ5xq5ieZc1mzmyfCt",
			wantErr: false,
		},
		{
			name:    "Invalid Org ID",
			input:   "InvalidOrgID",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v; wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignPeer(t *testing.T) {
	tests := []struct {
		name    string
		privKey crypto.PrivKey
		peerID  peer.ID
		wantErr bool
		wantSig string
	}{
		{
			name:    "Sign peer with invalid key",
			privKey: crypto.PrivKey(nil), // Invalid private key
			peerID:  peer.ID("QmTestPeerID"),
			wantErr: true,
			wantSig: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignPeer(tt.privKey, tt.peerID)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignPeer() error = %v; wantErr %v", err, tt.wantErr)
			}
			if got != tt.wantSig {
				t.Errorf("SignPeer() = %v; want %v", got, tt.wantSig)
			}
		})
	}
}
