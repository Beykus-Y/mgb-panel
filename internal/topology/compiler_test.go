package topology

import (
	"strings"
	"testing"

	"mgb-panel/internal/model"
)

func TestCompileNodeConfig(t *testing.T) {
	cfg, err := CompileNodeConfig(
		model.Node{ID: "node_1", Name: "edge-1"},
		[]model.InboundProfile{{
			ID:            "in_1",
			Name:          "main",
			Protocol:      "vless",
			ListenHost:    "::",
			ListenPort:    443,
			Transport:     "ws",
			Path:          "/x",
			ServerName:    "vpn.example.com",
			TLSMode:       "reality",
			RealityPubKey: "pub",
			RealityPrivateKey:     "priv",
			RealityHandshakeServer: "www.cloudflare.com",
			RealityHandshakePort:   443,
			RealityShort:  "abcd",
		}},
		[]model.TopologyLink{{
			ID:           "link_1",
			SourceNodeID: "node_1",
			TargetNodeID: "node_2",
			EndpointHost: "relay.internal",
			EndpointPort: 51820,
			AllowedCIDRs: "10.0.0.0/8, 192.168.0.0/16",
		}},
		[]model.User{{Name: "alice", AccessKey: "11111111-1111-4111-8111-111111111111"}},
	)
	if err != nil {
		t.Fatalf("CompileNodeConfig: %v", err)
	}
	text := string(cfg)
	for _, needle := range []string{"\"wireguard\"", "\"vless\"", "\"private_key\": \"priv\"", "relay.internal", "192.168.0.0/16"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("config missing %q in %s", needle, text)
		}
	}
}

func TestCompileNodeConfigRejectsInvalidCombination(t *testing.T) {
	_, err := CompileNodeConfig(
		model.Node{ID: "node_1", Name: "edge-1"},
		[]model.InboundProfile{{
			ID:         "in_1",
			Name:       "hy2",
			Protocol:   "hysteria2",
			ListenHost: "::",
			ListenPort: 443,
			TLSMode:    "reality",
			Password:   "secret",
		}},
		nil,
		[]model.User{{Name: "alice", AccessKey: "11111111-1111-4111-8111-111111111111"}},
	)
	if err == nil {
		t.Fatal("expected invalid inbound combination error")
	}
}
