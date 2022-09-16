// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"context"
	"crypto/tls"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/mak"
	"tailscale.com/util/multierr"
)

// noiseConn is a wrapper around controlbase.Conn.
// It allows attaching an ID to a connection to allow
// cleaning up references in the pool when the connection
// is closed.
type noiseConn struct {
	*controlbase.Conn
	id   int
	pool *noiseClient
}

func (c *noiseConn) Close() error {
	if err := c.Conn.Close(); err != nil {
		return err
	}
	c.pool.connClosed(c.id)
	return nil
}

// noiseClient provides a http.Client to connect to tailcontrol over
// the ts2021 protocol.
type noiseClient struct {
	*http.Client // HTTP client used to talk to tailcontrol
	dialer       *tsdial.Dialer
	privKey      key.MachinePrivate
	serverPubKey key.MachinePublic
	host         string // the host part of serverURL
	httpPort     string // the default port to call
	httpsPort    string // the fallback Noise-over-https port

	// Optional DialPlan received from the control server previously; can
	// be nil.
	dialPlan *atomic.Pointer[tailcfg.ControlDialPlan]

	// mu only protects the following variables.
	mu       sync.Mutex
	nextID   int
	connPool map[int]*noiseConn // active connections not yet closed; see noiseConn.Close
}

// newNoiseClient returns a new noiseClient for the provided server and machine key.
// serverURL is of the form https://<host>:<port> (no trailing slash).
func newNoiseClient(priKey key.MachinePrivate, serverPubKey key.MachinePublic, serverURL string, dialer *tsdial.Dialer, dialPlan *atomic.Pointer[tailcfg.ControlDialPlan]) (*noiseClient, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}
	var httpPort string
	var httpsPort string
	if u.Port() != "" {
		// If there is an explicit port specified, trust the scheme and hope for the best
		if u.Scheme == "http" {
			httpPort = u.Port()
			httpsPort = "443"
		} else {
			httpPort = "80"
			httpsPort = u.Port()
		}
	} else {
		// Otherwise, use the standard ports
		httpPort = "80"
		httpsPort = "443"
	}
	np := &noiseClient{
		serverPubKey: serverPubKey,
		privKey:      priKey,
		host:         u.Hostname(),
		httpPort:     httpPort,
		httpsPort:    httpsPort,
		dialer:       dialer,
		dialPlan:     dialPlan,
	}

	// Create the HTTP/2 Transport using a net/http.Transport
	// (which only does HTTP/1) because it's the only way to
	// configure certain properties on the http2.Transport. But we
	// never actually use the net/http.Transport for any HTTP/1
	// requests.
	h2Transport, err := http2.ConfigureTransports(&http.Transport{
		IdleConnTimeout: time.Minute,
	})
	if err != nil {
		return nil, err
	}

	// Let the HTTP/2 Transport think it's dialing out using TLS,
	// but it's actually our Noise dialer:
	h2Transport.DialTLS = np.dial

	// ConfigureTransports assumes it's being used to wire up an HTTP/1
	// and HTTP/2 Transport together, so its returned http2.Transport
	// has a ConnPool already initialized that's configured to not dial
	// (assuming it's only called from the HTTP/1 Transport). But we
	// want it to dial, so nil it out before use. On first use it has
	// a sync.Once that lazily initializes the ConnPool to its default
	// one that dials.
	h2Transport.ConnPool = nil

	np.Client = &http.Client{Transport: h2Transport}
	return np, nil
}

// connClosed removes the connection with the provided ID from the pool
// of active connections.
func (nc *noiseClient) connClosed(id int) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	delete(nc.connPool, id)
}

// Close closes all the underlying noise connections.
// It is a no-op and returns nil if the connection is already closed.
func (nc *noiseClient) Close() error {
	nc.mu.Lock()
	conns := nc.connPool
	nc.connPool = nil
	nc.mu.Unlock()

	var errors []error
	for _, c := range conns {
		if err := c.Close(); err != nil {
			errors = append(errors, err)
		}
	}
	return multierr.New(errors...)
}

// dial opens a new connection to tailcontrol, fetching the server noise key
// if not cached. It implements the signature needed by http2.Transport.DialTLS
// but ignores all params as it only dials out to the server the noiseClient was
// created for.
func (nc *noiseClient) dial(_, _ string, _ *tls.Config) (net.Conn, error) {
	nc.mu.Lock()
	connID := nc.nextID
	nc.nextID++
	nc.mu.Unlock()

	if tailcfg.CurrentCapabilityVersion > math.MaxUint16 {
		// Panic, because a test should have started failing several
		// thousand version numbers before getting to this point.
		panic("capability version is too high to fit in the wire protocol")
	}

	// TODO(andrew): remove after testing
	//dialPlan := nc.dialPlan
	dialPlan := fakeDialPlan

	// If we have a dial plan, then set our timeout as slightly longer than
	// the maximum amount of time contained therein; we assume that
	// explicit instructions on timeouts are more useful than a single
	// hard-coded timeout.
	//
	// The default value of 5 is chosen so that, when there's no dial plan,
	// we retain the previous behaviour of 10 seconds end-to-end timeout.
	var timeoutSec float64 = 5
	if dialPlan != nil {
		if dp := dialPlan.Load(); dp != nil && len(dp.Candidates) > 0 {
			for _, c := range dp.Candidates {
				if v := c.DialStartDelaySec + c.DialTimeoutSec; v > timeoutSec {
					timeoutSec = v
				}
			}
		}
	}

	// After we establish a connection, we need some time to actually
	// upgrade it into a Noise connection. With a ballpark worst-case RTT
	// of 1000ms, give ourselves an extra 5 seconds to complete the
	// handshake.
	timeoutSec += 5

	// Be extremely defensive and ensure that the timeout is in the range
	// [5, 60] seconds (e.g. if we accidentally get a negative number).
	if timeoutSec > 60 {
		timeoutSec = 60
	} else if timeoutSec < 5 {
		timeoutSec = 5
	}

	timeout := time.Duration(timeoutSec * float64(time.Second))
	log.Printf("controlclient: Noise dial timeout: %v", timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := (&controlhttp.Dialer{
		Host:            nc.host,
		HTTPPort:        nc.httpPort,
		HTTPSPort:       nc.httpsPort,
		MachineKey:      nc.privKey,
		ControlKey:      nc.serverPubKey,
		ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion),
		Dialer:          nc.dialer.SystemDial,
		DialPlan:        dialPlan,

		// TODO(andrew): remove after testing
		Logf: log.Printf,
	}).Dial(ctx)
	if err != nil {
		return nil, err
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()
	ncc := &noiseConn{Conn: conn, id: connID, pool: nc}
	mak.Set(&nc.connPool, ncc.id, ncc)
	return ncc, nil
}

// TODO(andrew): remove after testing
var fakeDialPlan = (func() *atomic.Pointer[tailcfg.ControlDialPlan] {
	ret := new(atomic.Pointer[tailcfg.ControlDialPlan])
	ret.Store(&tailcfg.ControlDialPlan{
		Candidates: []tailcfg.ControlIPCandidate{
			// First; fails
			{IP: netip.MustParseAddr("13.0.0.1"), DialTimeoutSec: 10, Priority: 3},

			// Succeed
			{IP: netip.MustParseAddr("18.157.173.201"), DialStartDelaySec: 0.5, DialTimeoutSec: 9.5, Priority: 1},
			{IP: netip.MustParseAddr("2a05:d014:386:201:7200:6340:b22f:7df6"), DialStartDelaySec: 0.5, DialTimeoutSec: 9.5, Priority: 2},
		},
	})
	return ret
})()
