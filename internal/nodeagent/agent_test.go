package nodeagent

import (
	"testing"
)

func TestPEMFingerprintRejectsGarbage(t *testing.T) {
	if _, err := pemFingerprint([]byte("not a pem")); err == nil {
		t.Fatal("expected pem decode failure")
	}
}

func TestTrafficFromStatsAggregatesAllDimensions(t *testing.T) {
	items := trafficFromStats("node_1", []*stat{
		{Name: "user>>>user_1@in_1>>>traffic>>>uplink", Value: 100},
		{Name: "user>>>user_1@in_1>>>traffic>>>downlink", Value: 200},
		{Name: "inbound>>>in_1>>>traffic>>>uplink", Value: 110},
		{Name: "inbound>>>in_1>>>traffic>>>downlink", Value: 220},
	})

	seen := map[string]int64{}
	for _, item := range items {
		seen[item.UserID+"/"+item.InboundID] = item.Uplink + item.Downlink
	}
	if seen["user_1/in_1"] != 300 {
		t.Fatalf("client by inbound total = %d", seen["user_1/in_1"])
	}
	if seen["user_1/"] != 300 {
		t.Fatalf("client total = %d", seen["user_1/"])
	}
	if seen["/in_1"] != 330 {
		t.Fatalf("inbound total = %d", seen["/in_1"])
	}
	if seen["/"] != 330 {
		t.Fatalf("node total = %d", seen["/"])
	}
}
