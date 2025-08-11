package tor

import (
	"context"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/proxy"
)

// DialConf is the configuration used for Dialer.
type DialConf struct {
	// ProxyAddress is the address for the SOCKS5 proxy. If empty, it is looked
	// up.
	ProxyAddress string

	// ProxyNetwork is the network for the SOCKS5 proxy. If ProxyAddress is
	// empty, this value is ignored and overridden by what is looked up. If this
	// is empty and ProxyAddress is not empty, it defaults to "tcp".
	ProxyNetwork string

	// ProxyAuth is the auth for the proxy. Since Tor's SOCKS5 proxy is
	// unauthenticated, this is rarely needed. It can be used when
	// IsolateSOCKSAuth is set to ensure separate circuits.
	//
	// This should not be confused with downstream SOCKS proxy authentication
	// which is set via Tor values for Socks5ProxyUsername and
	// Socks5ProxyPassword when Socks5Proxy is set.
	ProxyAuth *proxy.Auth

	// SkipEnableNetwork, if true, will skip the enable network step in Dialer.
	SkipEnableNetwork bool

	// Forward is the dialer to forward to. If nil, just uses normal net dialer.
	Forward proxy.Dialer
}

// Dialer creates a new Dialer for the given configuration. Context can be nil.
// If conf is nil, a default is used.
func (t *Tor) Dialer(ctx context.Context, conf *DialConf) (proxy.ContextDialer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if conf == nil {
		conf = &DialConf{}
	}
	// Enable the network if requested
	if !conf.SkipEnableNetwork {
		if err := t.EnableNetwork(ctx, true); err != nil {
			return nil, err
		}
	}
	// Lookup proxy address as needed
	proxyNetwork := conf.ProxyNetwork
	proxyAddress := conf.ProxyAddress
	if proxyAddress == "" {
		info, err := t.Control.GetInfo("net/listeners/socks")
		if err != nil {
			return nil, err
		}
		if len(info) != 1 || info[0].Key != "net/listeners/socks" {
			return nil, fmt.Errorf("Unable to get socks proxy address")
		}
		proxyAddress = info[0].Val
		if strings.HasPrefix(proxyAddress, "unix:") {
			proxyAddress = proxyAddress[5:]
			proxyNetwork = "unix"
		} else {
			proxyNetwork = "tcp"
		}
	} else if proxyNetwork == "" {
		proxyNetwork = "tcp"
	}

	dialer, err := proxy.SOCKS5(proxyNetwork, proxyAddress, conf.ProxyAuth, conf.Forward)
	if err != nil {
		return nil, err
	}

	return &dialerCtxWrapper{dialer: dialer}, nil
}

type dialerCtxWrapper struct {
	dialer proxy.Dialer
}

func (w *dialerCtxWrapper) DialContext(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	return dialWithCtx(w.dialer.Dial)(ctx, network, address)
}

func dialWithCtx[Conn any](
	f func(string, string) (Conn, error),
) func(context.Context, string, string) (Conn, error) {
	return func(ctx context.Context, network, address string) (zeroConn Conn, err error) {
		chConn := make(chan Conn)
		chErr := make(chan error)

		go func() {
			conn, err := f(network, address)
			if err != nil {
				chErr <- err
				return
			}
			chConn <- conn
		}()

		select {
		case <-ctx.Done():
			return zeroConn, ctx.Err()
		case err := <-chErr:
			return zeroConn, err
		case conn := <-chConn:
			return conn, nil
		}
	}
}
