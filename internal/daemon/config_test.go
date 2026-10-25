package daemon

import (
	"io"
	"strings"
	"testing"
)

var requiredArgs = []string{"--device", "wg0", "--probe-config", "/etc/probe.conf", "--endpoints", "/etc/eps",
	"--probe-addr", "192.0.2.3", "--target", "192.0.2.1"}

func TestParseFlagsRequired(t *testing.T) {
	_, err := ParseFlags([]string{"--device", "wg0"}, DefaultConfig(), io.Discard)
	if err == nil {
		t.Fatal("missing required flags accepted")
	}
	for _, f := range []string{"--probe-config", "--endpoints", "--probe-addr", "--target"} {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error %q does not name %s", err, f)
		}
	}
}

func TestParseFlagsDefaults(t *testing.T) {
	c, err := ParseFlags(requiredArgs, DefaultConfig(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.NftTable != "wgsteer_wg0" {
		t.Errorf("nft table = %q, want wgsteer_wg0", c.NftTable)
	}
	if err := c.Params().Validate(); err != nil {
		t.Errorf("default policy params invalid: %v", err)
	}
	c, err = ParseFlags(append(requiredArgs, "--nft-table", "custom"), DefaultConfig(), io.Discard)
	if err != nil || c.NftTable != "custom" {
		t.Errorf("explicit --nft-table: %q, %v", c.NftTable, err)
	}
}

func TestParseFlagsRejectsTimeoutNotBelowInterval(t *testing.T) {
	for _, timeout := range []string{"1s", "2s"} {
		args := append(requiredArgs, "--probe-interval", "1s", "--probe-timeout", timeout)
		if _, err := ParseFlags(args, DefaultConfig(), io.Discard); err == nil || !strings.Contains(err.Error(), "--probe-timeout") {
			t.Errorf("timeout %s: err = %v, want a --probe-timeout error", timeout, err)
		}
	}
	args := append(requiredArgs, "--probe-interval", "1s", "--probe-timeout", "999ms")
	if _, err := ParseFlags(args, DefaultConfig(), io.Discard); err != nil {
		t.Errorf("timeout just below the interval rejected: %v", err)
	}
}

func TestParseFlagsRejectsInvalidPolicy(t *testing.T) {
	args := append(requiredArgs, "--history", "10", "--min-samples", "20")
	if _, err := ParseFlags(args, DefaultConfig(), io.Discard); err == nil || !strings.Contains(err.Error(), "min-samples") {
		t.Errorf("min-samples > history: err = %v", err)
	}
}

// --probe-size is bounded by --probe-mtu minus the inner IP and ICMP
// headers (28 bytes for IPv4, 48 for IPv6), and --probe-mtu by the
// family's minimum.
func TestParseFlagsProbeSizeBoundByMTU(t *testing.T) {
	v6 := []string{"--device", "wg0", "--probe-config", "/etc/probe.conf", "--endpoints", "/etc/eps",
		"--probe-addr", "fd00::3", "--target", "fd00::1"}
	for _, c := range []struct {
		args []string
		ok   bool
	}{
		{append(requiredArgs, "--probe-size", "1392"), true}, // default MTU 1420
		{append(requiredArgs, "--probe-size", "1393"), false},
		{append(requiredArgs, "--probe-mtu", "1380", "--probe-size", "1352"), true},
		{append(requiredArgs, "--probe-mtu", "1380", "--probe-size", "1353"), false},
		{append(requiredArgs, "--probe-mtu", "576"), true},
		{append(requiredArgs, "--probe-mtu", "575"), false},
		{append(v6, "--probe-mtu", "1280", "--probe-size", "1232"), true},
		{append(v6, "--probe-mtu", "1280", "--probe-size", "1233"), false},
		{append(v6, "--probe-mtu", "1279"), false},
	} {
		_, err := ParseFlags(c.args, DefaultConfig(), io.Discard)
		if (err == nil) != c.ok {
			t.Errorf("%v: err = %v, want ok=%v", c.args[len(c.args)-4:], err, c.ok)
		}
	}
}
