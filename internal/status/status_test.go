package status

import (
	"encoding/json"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bjin/wgsteer/internal/policy"
	"github.com/bjin/wgsteer/internal/stats"
)

func sample() *Status {
	at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	a := netip.MustParseAddrPort("10.0.0.1:4000")
	b := netip.MustParseAddrPort("[fd00::2]:4000")
	inf := policy.Float(math.Inf(1))
	return &Status{
		At:     at,
		Daemon: Daemon{Version: "v1", Revision: "abc", StartTime: at.Add(-time.Hour), State: StateRunning},
		Device: Device{Name: "wg0", Present: true, Type: "kernel", Endpoint: a, Listed: true},
		Selection: Selection{Endpoint: a, Index: 0, Name: "us", Since: at.Add(-time.Minute), Reason: `adopted "quoted"`,
			Rules:    []policy.RuleState{{Rule: policy.RuleDegrade, Value: time.Second, Hold: time.Minute}},
			Decision: Decision{Blocker: policy.BlockerNothingBetter, Reason: "nothing better\nbeyond noise"}},
		Endpoints: []Endpoint{
			{EndpointView: policy.EndpointView{Addr: a, Index: 0, Name: "us", Active: true, Samples: 20, Loss: 0.05, Cost: 150,
				Last: &stats.Sample{At: at.Add(-time.Second), Replied: true, RTT: 150 * time.Millisecond}}, Family: "ipv4"},
			{EndpointView: policy.EndpointView{Addr: b, Index: 1, Name: "1", Loss: 1, Cost: inf, BiasedCost: inf, Latency: inf,
				Gate: &policy.Gated{G: 0, RLat: policy.Float(math.Inf(-1))}}, Family: "ipv6", Denied: true, DenyPackets: 7},
		},
		NFT:     NFT{Enabled: true, Table: "wgsteer_wg0", Denied: []Counter{{Endpoint: b, Packets: 7}}},
		History: []SwitchEvent{{ID: 1, At: at, Kind: policy.KindDegrade, From: b, To: a, Result: ResultOK, Reason: "worse"}},
	}
}

func TestJSONHandlesInfiniteCost(t *testing.T) {
	b, err := json.Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	var back Status
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !math.IsInf(float64(back.Endpoints[1].Cost), 1) || back.Endpoints[1].Family != "ipv6" || back.Endpoints[1].Addr.Port() != 4000 {
		t.Fatalf("round trip lost data: %+v", back.Endpoints[1])
	}
}

func TestLinesOneRowPerRecord(t *testing.T) {
	lines := sample().Lines()
	text := strings.Join(lines, "\n")
	for _, l := range lines {
		if strings.ContainsAny(l, "\"\n") {
			t.Errorf("row %q contains a quote or newline", l)
		}
	}
	for _, want := range []string{"selection: #us 10.0.0.1:4000 ", "[fd00::2]:4000", "inf", "7 pkts", "nothing-better", "history: #1"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendering lacks %q:\n%s", want, text)
		}
	}
}
