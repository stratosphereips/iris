package peer_discovery

import (
	"happystoic/p2pnetwork/pkg/config"
	"testing"
	_ "testing"
)

// Mock configuration for testing
var mockConfig = config.PeerDiscovery{
	ListOfMultiAddresses: []string{
		"/ip4/127.0.0.1/udp/9001/quic-v1 12D3KooWLDCxxP6PAKG6NUYWs16VbSZhQNHY361otSmauvVnXV4g",
		"/ip4/127.0.0.1/udp/9003/quic-v1 12D3KooWLDCxxP6PAKG6NUYWs16VbSZh61otSmauvVnXV4gQNHY3",
	},
	DisableBootstrappingNodes: false,
	UseRedisCache:             false,
	UseDns:                    false,
}

func TestGetInitPeers(t *testing.T) {
	tests := []struct {
		name    string
		config  config.PeerDiscovery
		wantLen int
		wantErr bool
	}{
		{
			name:    "With valid static peers",
			config:  mockConfig,
			wantLen: 2, // expect 2 static peers in ListOfMultiAddresses
			wantErr: false,
		},
		{
			name: "With invalid connection string",
			config: config.PeerDiscovery{
				ListOfMultiAddresses: []string{
					"/ip4/127.0.0.1/udp/9001/quic-v1 invalidPeerID",
				},
				DisableBootstrappingNodes: true,
				UseRedisCache:             false,
				UseDns:                    false,
			},
			wantLen: 0,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetInitPeers(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetInitPeers() error = %v; wantErr %v", err, tt.wantErr)
			}
			if len(got) != tt.wantLen {
				t.Errorf("GetInitPeers() = %v; want %v", len(got), tt.wantLen)
			}
		})
	}
}

func TestAddrInfoFromConnectionString(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		wantErr bool
	}{
		{
			name:    "Valid connection string",
			s:       "/ip4/127.0.0.1/udp/9001/quic-v1 12D3KooWLDCxxP6PAKG6NUYWs16VbSZhQNHY361otSmauvVnXV4g",
			wantErr: false,
		},
		{
			name:    "Invalid connection string format",
			s:       "/ip4/127.0.0.1/tcp/4001", // Missing peerID
			wantErr: true,
		},
		{
			name:    "Invalid peerID",
			s:       "/ip4/127.0.0.1/tcp/4001 invalidPeerID", // Invalid peerID
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := addrInfoFromConnectionString(tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("addrInfoFromConnectionString() error = %v; wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got == nil {
				t.Errorf("addrInfoFromConnectionString() = nil; want non-nil AddrInfo")
			}
		})
	}
}
