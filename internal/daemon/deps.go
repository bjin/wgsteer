package daemon

import (
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/bjin/wgsteer/internal/nftable"
	"github.com/bjin/wgsteer/internal/probe"
	"github.com/bjin/wgsteer/internal/wgdev"
)

// Device is the live WireGuard device client (*wgdev.Client).
type Device interface {
	Get(name string) (*wgdev.Device, error)
	SetEndpoint(name string, peer wgtypes.Key, ep netip.AddrPort, keepalive time.Duration, kick bool) error
	Close() error
}

// Firewall is the daemon-owned nft table (*nftable.Manager).
type Firewall interface {
	Info() nftable.TableInfo
	Apply(rs nftable.Ruleset) ([]nftable.Counter, error)
	Committed() nftable.Ruleset
	Counters() ([]nftable.Counter, error)
	Reconnect(rs nftable.Ruleset) error
	Close() error
}

// Prober is the measurement probe (*probe.Probe).
type Prober interface {
	Retarget(ep netip.AddrPort) error
	SetFwmark(mark uint32) error
	Send(seq uint16, nonce uint64, endpointID uint32) error
	Replies() <-chan probe.Reply
	State() (probe.State, error)
	PublicKey() wgtypes.Key
	Close() error
}

// deps creates the daemon's external resources; tests substitute fakes.
type deps struct {
	dev      Device
	openNFT  func(table string) (Firewall, error)
	newProbe func(cfg probe.Config) (Prober, error)
}

func realDeps(dev Device) deps {
	return deps{
		dev: dev,
		openNFT: func(table string) (Firewall, error) {
			m, err := nftable.Open(table)
			if err != nil {
				return nil, err
			}
			return m, nil
		},
		newProbe: func(cfg probe.Config) (Prober, error) {
			p, err := probe.New(cfg)
			if err != nil {
				return nil, err
			}
			return p, nil
		},
	}
}
