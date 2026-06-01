package reliability

import (
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
)

// TestNewBook checks that a new Book is initialized correctly.
func TestNewBook(t *testing.T) {
	book := NewBook()
	assert.NotNil(t, book)
	assert.Empty(t, book.peersRel)
	assert.Empty(t, book.callbacks)
}

// TestUpdatePeerRel verifies that a peer's reliability score is updated correctly.
func TestUpdatePeerRel(t *testing.T) {
	book := NewBook()
	p := peer.ID("peer1")
	expectedRel := Reliability(0.75)

	book.UpdatePeerRel(p, expectedRel)

	assert.Equal(t, expectedRel, book.PeerRel(p), "Peer reliability should be updated correctly")
}

// TestPeerRel checks that a peer's reliability is retrieved correctly.
func TestPeerRel(t *testing.T) {
	book := NewBook()
	p := peer.ID("peer1")

	// Initially, the reliability should be the default
	assert.Equal(t, Reliability(DefaultReliability), book.PeerRel(p), "Default reliability should be returned if peer not set")

	expectedRel := Reliability(0.9)
	book.UpdatePeerRel(p, expectedRel)

	assert.Equal(t, expectedRel, book.PeerRel(p), "Updated reliability should be returned")
}

// TestExpTransformedPeerRel ensures the exponential transformation is applied correctly.
func TestExpTransformedPeerRel(t *testing.T) {
	book := NewBook()
	p := peer.ID("peer1")

	// Setting a known reliability
	book.UpdatePeerRel(p, 1.0)
	expected := uint((math.Pow(10, 1.0) - 1) / (10 - 1) * 1000)

	assert.Equal(t, expected, book.ExpTransformedPeerRel(p), "Exponential transformation should be applied correctly")

	// Edge case: Default reliability
	p2 := peer.ID("peer2")
	expectedDefault := uint((math.Pow(10, float64(DefaultReliability)) - 1) / (10 - 1) * 1000)
	assert.Equal(t, expectedDefault, book.ExpTransformedPeerRel(p2), "Default reliability should return correct transformed value")
}

// TestSubscribeForChange verifies that callbacks are triggered when reliability is updated.
func TestSubscribeForChange(t *testing.T) {
	book := NewBook()
	p := peer.ID("peer1")
	expectedRel := Reliability(0.85)

	callbackTriggered := false
	book.SubscribeForChange(func(peerID peer.ID, rel Reliability) {
		callbackTriggered = true
		assert.Equal(t, p, peerID, "Callback should receive the correct peer ID")
		assert.Equal(t, expectedRel, rel, "Callback should receive the correct reliability value")
	})

	book.UpdatePeerRel(p, expectedRel)

	assert.True(t, callbackTriggered, "Callback should have been triggered")
}
