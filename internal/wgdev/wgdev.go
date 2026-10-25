// Package wgdev reads and updates the live WireGuard device through wgctrl
// (genetlink for kernel WireGuard, the UAPI socket for userspace
// implementations). It only ever changes the managed peer's endpoint and
// persistent keepalive, always with UpdateOnly, and never keys, allowed IPs
// or other peers.
package wgdev

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/bjin/wgsteer/internal/endpoints"
)

// ErrNotFound reports that the device does not exist (or is not a WireGuard
// device).
var ErrNotFound = errors.New("wireguard device not found")

// Peer is the part of a peer the daemon reads.
type Peer struct {
	PublicKey     wgtypes.Key
	Endpoint      netip.AddrPort // normalized (unmapped); zero if unset
	Keepalive     time.Duration
	LastHandshake time.Time // zero if never
	RxBytes       int64
	TxBytes       int64
}

// Device is a snapshot of the live device.
type Device struct {
	Name       string
	Type       string // "kernel" or "userspace" (other kernels: wgctrl's name)
	PublicKey  wgtypes.Key
	ListenPort int
	Fwmark     uint32
	Peers      []Peer
}

// Peer returns the peer with public key k.
func (d *Device) Peer(k wgtypes.Key) (Peer, bool) {
	for _, p := range d.Peers {
		if p.PublicKey == k {
			return p, true
		}
	}
	return Peer{}, false
}

// Client wraps a wgctrl client. It is not safe for concurrent use.
type Client struct {
	c *wgctrl.Client
}

// Open creates a wgctrl client.
func Open() (*Client, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgdev: open wgctrl: %w", err)
	}
	return &Client{c: c}, nil
}

// Close releases the wgctrl client.
func (c *Client) Close() error { return c.c.Close() }

// Get reads the device. A missing device returns an error wrapping
// ErrNotFound.
func (c *Client) Get(name string) (*Device, error) {
	d, err := c.c.Device(name)
	if err != nil {
		return nil, wrap("get "+name, err)
	}
	dev := &Device{
		Name:       d.Name,
		Type:       deviceType(d.Type),
		PublicKey:  d.PublicKey,
		ListenPort: d.ListenPort,
		Fwmark:     uint32(d.FirewallMark),
		Peers:      make([]Peer, len(d.Peers)),
	}
	for i, p := range d.Peers {
		dev.Peers[i] = Peer{
			PublicKey:     p.PublicKey,
			Endpoint:      endpoints.FromUDPAddr(p.Endpoint),
			Keepalive:     p.PersistentKeepaliveInterval,
			LastHandshake: p.LastHandshakeTime,
			RxBytes:       p.ReceiveBytes,
			TxBytes:       p.TransmitBytes,
		}
	}
	return dev, nil
}

func deviceType(t wgtypes.DeviceType) string {
	switch t {
	case wgtypes.LinuxKernel:
		return "kernel"
	case wgtypes.Userspace:
		return "userspace"
	}
	return t.String()
}

// SetEndpoint points the managed peer at ep with UpdateOnly, so a peer that
// does not exist is silently not created (the next Get shows it missing).
//
// With kick=false only the endpoint is set. With kick=true it also forces an
// immediate keepalive through the new endpoint, given the
// peer's original keepalive K:
//   - K>0: {endpoint, keepalive 0}, then {keepalive K};
//   - K=0: {endpoint, keepalive 0}, then {keepalive 1s}, then {keepalive 0}.
//
// The 0→nonzero transition is what makes WireGuard send the keepalive; it
// needs the interface to be up. Both branches start at keepalive 0, so the
// transition happens even when a failed earlier kick left 1s behind. A
// failure between the calls can leave the keepalive at 0 or 1s; the error
// names the call that failed.
func (c *Client) SetEndpoint(name string, peer wgtypes.Key, ep netip.AddrPort, keepalive time.Duration, kick bool) error {
	if !ep.IsValid() {
		return fmt.Errorf("wgdev: set endpoint on %s: invalid endpoint %v", name, ep)
	}
	ep = endpoints.Normalize(ep)
	keepalive = keepalive.Truncate(time.Second)
	set := func(step string, withEndpoint bool, ka *time.Duration) error {
		pc := wgtypes.PeerConfig{
			PublicKey:                   peer,
			UpdateOnly:                  true,
			PersistentKeepaliveInterval: ka,
		}
		if withEndpoint {
			pc.Endpoint = endpoints.ToUDPAddr(ep)
		}
		err := c.c.ConfigureDevice(name, wgtypes.Config{Peers: []wgtypes.PeerConfig{pc}})
		if err != nil {
			return wrap(fmt.Sprintf("%s (%s, endpoint %v)", step, name, ep), err)
		}
		return nil
	}

	if !kick {
		return set("set endpoint", true, nil)
	}
	if keepalive > 0 {
		if err := set("set endpoint and keepalive 0", true, new(time.Duration(0))); err != nil {
			return err
		}
		return set(fmt.Sprintf("restore keepalive %v", keepalive), false, new(keepalive))
	}
	if err := set("set endpoint and keepalive 0", true, new(time.Duration(0))); err != nil {
		return err
	}
	if err := set("kick keepalive 1s", false, new(time.Second)); err != nil {
		return err
	}
	return set("restore keepalive 0", false, new(time.Duration(0)))
}

func wrap(op string, err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("wgdev: %s: %w", op, ErrNotFound)
	}
	return fmt.Errorf("wgdev: %s: %w", op, err)
}
