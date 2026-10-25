// Package probecfg parses the probe identity: a WireGuard xplatform UAPI "set"
// configuration with hex keys and exactly one peer.
package probecfg

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/bjin/wgsteer/internal/endpoints"
)

// Config is the probe's WireGuard identity and its single peer.
type Config struct {
	PrivateKey wgtypes.Key
	PublicKey  wgtypes.Key // derived from PrivateKey
	ListenPort int         // 0 picks a random port

	PeerKey      wgtypes.Key
	PresharedKey *wgtypes.Key
	AllowedIPs   []netip.Prefix
	Endpoint     netip.AddrPort // optional; the daemon overrides it
	Keepalive    int            // persistent_keepalive_interval in seconds; 0 when unset
}

// Load reads and parses a probe configuration file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open probe config: %w", err)
	}
	defer f.Close()
	c, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse reads a UAPI set configuration. Blank lines and '#' comments are
// allowed in addition to the plain UAPI syntax.
func Parse(r io.Reader) (*Config, error) {
	var (
		c        Config
		havePriv bool
		peers    int
	)
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key=value", lineNo)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		inPeer := peers > 0
		var err error
		switch {
		case key == "private_key" && !inPeer:
			c.PrivateKey, err = parseHexKey(value)
			havePriv = true
		case key == "listen_port" && !inPeer:
			c.ListenPort, err = parsePort(value)
		case key == "replace_peers" && !inPeer:
			err = expectTrue(value)
		case key == "fwmark" && !inPeer:
			err = fmt.Errorf("fwmark is copied from the live device; remove it")
		case key == "public_key":
			peers++
			if peers > 1 {
				return nil, fmt.Errorf("line %d: exactly one peer is allowed", lineNo)
			}
			c.PeerKey, err = parseHexKey(value)
		case key == "preshared_key" && inPeer:
			var k wgtypes.Key
			if k, err = parseHexKey(value); err == nil {
				c.PresharedKey = &k
			}
		case key == "endpoint" && inPeer:
			c.Endpoint, err = endpoints.ParseOne(value)
		case key == "allowed_ip" && inPeer:
			var p netip.Prefix
			if p, err = netip.ParsePrefix(value); err == nil {
				c.AllowedIPs = append(c.AllowedIPs, p.Masked())
			}
		case key == "replace_allowed_ips" && inPeer:
			err = expectTrue(value)
		case key == "persistent_keepalive_interval" && inPeer:
			c.Keepalive, err = strconv.Atoi(value)
			if err == nil && (c.Keepalive < 0 || c.Keepalive > 65535) {
				err = fmt.Errorf("out of range")
			}
		case key == "protocol_version" && inPeer:
			if value != "1" {
				err = fmt.Errorf("unsupported protocol version")
			}
		default:
			return nil, fmt.Errorf("line %d: unexpected key %q", lineNo, key)
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", lineNo, key, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read probe config: %w", err)
	}
	if !havePriv {
		return nil, fmt.Errorf("missing private_key")
	}
	if peers != 1 {
		return nil, fmt.Errorf("exactly one peer (public_key) is required")
	}
	c.PublicKey = c.PrivateKey.PublicKey()
	if c.PublicKey == c.PeerKey {
		return nil, fmt.Errorf("peer public_key equals the probe's own public key")
	}
	return &c, nil
}

// Validate checks the probe addressing and fills defaults: without any
// allowed_ip the probe routes only the target's host prefix.
func (c *Config) Validate(probeAddr, target netip.Addr) error {
	if !probeAddr.IsValid() || !target.IsValid() {
		return fmt.Errorf("probe address and target are required")
	}
	probeAddr, target = probeAddr.Unmap(), target.Unmap()
	if probeAddr.Is4() != target.Is4() {
		return fmt.Errorf("probe address %s and target %s are different families", probeAddr, target)
	}
	if probeAddr == target {
		return fmt.Errorf("probe address equals target %s", target)
	}
	if len(c.AllowedIPs) == 0 {
		c.AllowedIPs = []netip.Prefix{netip.PrefixFrom(target, target.BitLen())}
		return nil
	}
	for _, p := range c.AllowedIPs {
		if p.Contains(target) {
			return nil
		}
	}
	return fmt.Errorf("target %s is not inside the peer's allowed_ip", target)
}

// CheckDevice validates the probe identity against the live device: the
// probe's peer must be a peer of the device, and the probe must not share the
// device's identity (the server would flap the live peer).
func (c *Config) CheckDevice(devicePublicKey wgtypes.Key, devicePeers []wgtypes.Key) error {
	if c.PublicKey == devicePublicKey {
		return fmt.Errorf("probe identity equals the device's own public key %s; the probe needs its own key", devicePublicKey)
	}
	for _, k := range devicePeers {
		if k == c.PeerKey {
			return nil
		}
	}
	return fmt.Errorf("peer public key %s not found on the device", c.PeerKey)
}

// UAPI renders the full IpcSet configuration that creates the probe peer
// with endpoint ep. The endpoint must be part of the creating IpcSet so
// wireguard-go disables roaming for the peer. fwmark is included when
// nonzero. Private keys appear only in this string; never log it.
func (c *Config) UAPI(ep netip.AddrPort, fwmark uint32) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(c.PrivateKey[:]))
	fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	if fwmark != 0 {
		fmt.Fprintf(&b, "fwmark=%d\n", fwmark)
	}
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(c.PeerKey[:]))
	if c.PresharedKey != nil {
		fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(c.PresharedKey[:]))
	}
	fmt.Fprintf(&b, "endpoint=%s\n", ep)
	b.WriteString("replace_allowed_ips=true\n")
	for _, p := range c.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p)
	}
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.Keepalive)
	}
	return b.String()
}

// HexKey renders a key in UAPI hex form.
func HexKey(k wgtypes.Key) string {
	return hex.EncodeToString(k[:])
}

func parseHexKey(s string) (wgtypes.Key, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != wgtypes.KeyLen {
		return wgtypes.Key{}, fmt.Errorf("expected %d hex-encoded bytes", wgtypes.KeyLen)
	}
	return wgtypes.NewKey(b)
}

func parsePort(s string) (int, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return int(n), nil
}

func expectTrue(s string) error {
	if s != "true" {
		return fmt.Errorf("only \"true\" is supported")
	}
	return nil
}
