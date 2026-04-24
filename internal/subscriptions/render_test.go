package subscriptions

import (
	"strings"
	"testing"

	"mgb-panel/internal/model"
)

func TestRenderURI(t *testing.T) {
	ep := Endpoint{
		NodeName: "edge-1",
		Host:     "vpn.example.com",
		User: model.User{
			AccessKey: "11111111-1111-4111-8111-111111111111",
		},
		Profile: model.InboundProfile{
			Name:          "edge-vless",
			Protocol:      "vless",
			ListenPort:    443,
			Transport:     "ws",
			Path:          "/connect",
			ServerName:    "vpn.example.com",
			TLSMode:       "reality",
			RealityPubKey: "pubkey",
			RealityShort:  "abcd",
		},
	}

	uri := RenderURI(ep)
	for _, part := range []string{"vless://", "vpn.example.com:443", "pbk=pubkey", "sid=abcd"} {
		if !strings.Contains(uri, part) {
			t.Fatalf("uri %q does not contain %q", uri, part)
		}
	}
}
