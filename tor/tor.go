package tor

import (
	"context"
	"fmt"
	"io"
	"net/textproto"
	"strconv"

	"github.com/cretz/bine/control"
)

const (
	DefaultControlPort = 9051
)

// Tor is the wrapper around the Tor process and control port connection. It
// should be created with Start and developers should always call Close when
// done.
type Tor struct {
	// Control is the Tor controller connection.
	Control *control.Conn

	// ControlPort is the port that Control is connected on. It is 0 if the
	// connection is an embedded control connection.
	ControlPort int

	// DebugWriter is the writer used for debug logs, or nil if debug logs
	// should not be emitted.
	DebugWriter io.Writer

	// GeoIPCreatedFile is the path, relative to DataDir, that was created from
	// StartConf.GeoIPFileReader. It is empty if no file was created.
	GeoIPCreatedFile string

	// GeoIPv6CreatedFile is the path, relative to DataDir, that was created
	// from StartConf.GeoIPFileReader. It is empty if no file was created.
	GeoIPv6CreatedFile string
}

// StartConf is the configuration used for Start when starting a Tor instance. A
// default instance with no fields set is the default used for Start.
type StartConf struct {
	// ControlPort is the port to use for the Tor controller. If it is 0, Tor
	// picks a port for use.
	ControlPort int

	// DisableCookieAuth, if true, will not use the default SAFECOOKIE
	// authentication mechanism for the Tor controller.
	DisableCookieAuth bool

	// DisableEagerAuth, if true, will not authenticate on Start.
	DisableEagerAuth bool

	// EnableNetwork, if true, will connect to the wider Tor network on start.
	EnableNetwork bool

	// DebugWriter is the writer to use for debug logs, or nil for no debug
	// logs.
	DebugWriter io.Writer

	// NoHush if true does not set --hush. By default --hush is set.
	NoHush bool

	// GeoIPReader, if present, is called before start to copy geo IP files to
	// the data directory. Errors are propagated. If the ReadCloser is present,
	// it is copied to the data dir, overwriting as necessary, and then closed
	// and the appropriate command line argument is added to reference it. If
	// both the ReadCloser and error are nil, no copy or command line argument
	// is used for that version. This is called twice, once with false and once
	// with true for ipv6.
	//
	// This can be set to torutil/geoipembed.GeoIPReader to use an embedded
	// source.
	GeoIPFileReader func(ipv6 bool) (io.ReadCloser, error)
}

// Start a Tor instance and connect to it. If ctx is nil, context.Background()
// is used. If conf is nil, a default instance is used.
func Start(ctx context.Context, conf *StartConf) (*Tor, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if conf == nil {
		conf = &StartConf{}
	}
	if conf.ControlPort == 0 {
		conf.ControlPort = DefaultControlPort
	}
	tor := &Tor{DebugWriter: conf.DebugWriter, ControlPort: conf.ControlPort}

	err := tor.connectController(ctx, conf)
	if err != nil {
		return nil, err
	}
	// Attempt eager auth w/ no password
	if !conf.DisableEagerAuth {
		err = tor.Control.Authenticate("")
		if err != nil {
			return nil, err
		}
	}

	return tor, nil
}

func (t *Tor) connectController(ctx context.Context, conf *StartConf) error {
	// This doesn't apply if already connected (e.g. using embedded conn)
	if t.Control != nil {
		return nil
	}
	t.Debugf("Connecting to control port %v", t.ControlPort)
	dialer := dialWithCtx(textproto.Dial)
	textConn, err := dialer(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(t.ControlPort))
	if err != nil {
		return err
	}
	t.Control = control.NewConn(textConn)
	t.Control.DebugWriter = t.DebugWriter
	return nil
}

// EnableNetwork sets DisableNetwork to 0 and optionally waits for bootstrap to
// complete. The context can be nil. If DisableNetwork isnt 1, this does
// nothing.
func (t *Tor) EnableNetwork(ctx context.Context, wait bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Only enable if DisableNetwork is 1
	if vals, err := t.Control.GetConf("DisableNetwork"); err != nil {
		return err
	} else if len(vals) == 0 || vals[0].Key != "DisableNetwork" || vals[0].Val != "1" {
		return nil
	}
	// Enable the network
	if err := t.Control.SetConf(control.KeyVals("DisableNetwork", "0")...); err != nil {
		return nil
	}
	// If not waiting, leave
	if !wait {
		return nil
	}
	// Wait for progress to hit 100
	_, err := t.Control.EventWait(ctx, []control.EventCode{control.EventCodeStatusClient},
		func(evt control.Event) (bool, error) {
			if status, _ := evt.(*control.StatusEvent); status != nil && status.Action == "BOOTSTRAP" {
				if status.Severity == "NOTICE" && status.Arguments["PROGRESS"] == "100" {
					return true, nil
				} else if status.Severity == "ERR" {
					return false, fmt.Errorf("Failing bootstrapping, Tor warning: %v", status.Arguments["WARNING"])
				}
			}
			return false, nil
		})
	return err
}
