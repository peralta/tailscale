// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlhttp

import (
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"tailscale.com/net/dnscache"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	// upgradeHeader is the value of the Upgrade HTTP header used to
	// indicate the Tailscale control protocol.
	upgradeHeaderValue = "tailscale-control-protocol"

	// handshakeHeaderName is the HTTP request header that can
	// optionally contain base64-encoded initial handshake
	// payload, to save an RTT.
	handshakeHeaderName = "X-Tailscale-Handshake"

	// serverUpgradePath is where the server-side HTTP handler to
	// to do the protocol switch is located.
	serverUpgradePath = "/ts2021"
)

// Dialer contains configuration on how to dial the Tailscale control server.
type Dialer struct {
	// Host is the host to connect to.
	//
	// This field is required.
	Host string

	// HTTPPort is the port number to use when making a HTTP connection.
	//
	// This field is required.
	HTTPPort string

	// HTTPSPort is the port number to use when making a HTTPS connection.
	//
	// This field is required.
	HTTPSPort string

	// MachineKey contains the current machine's private key.
	//
	// This field is required.
	MachineKey key.MachinePrivate

	// ControlKey contains the expected public key for the control server.
	//
	// This field is required.
	ControlKey key.MachinePublic

	// ProtocolVersion is the expected protocol version to negotiate.
	//
	// This field is required.
	ProtocolVersion uint16

	// Dialer is the dialer used to make outbound connections.
	//
	// This field is required.
	Dialer dnscache.DialContextFunc

	// Logf, if set, is a logging function to use; if unset, logs are
	// dropped.
	Logf logger.Logf

	// DialPlan, if set, contains instructions from the control server on
	// how to connect to it. If present, we will try the methods in this
	// plan before falling back to DNS.
	DialPlan *atomic.Pointer[tailcfg.ControlDialPlan]

	proxyFunc func(*http.Request) (*url.URL, error) // or nil

	// For tests only
	drainFinished     chan struct{}
	insecureTLS       bool
	testFallbackDelay time.Duration
}
