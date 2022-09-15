// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlhttp

import (
	"sync/atomic"

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

// DialOpts contains options when calling Dial.
type DialOpts struct {
	// The following fields are required

	// Host is the host to connect to.
	Host string

	// HTTPPort is the port number to use when making a HTTP connection.
	HTTPPort string

	// HTTPSPort is the port number to use when making a HTTPS connection.
	HTTPSPort string

	// MachineKey contains the current machine's private key.
	MachineKey key.MachinePrivate

	// ControlKey contains the expected public key for the control server.
	ControlKey key.MachinePublic

	// ProtocolVersion is the expected protocol version to negotiate.
	ProtocolVersion uint16

	// Dialer is the dialer used to make outbound connections.
	Dialer dnscache.DialContextFunc

	// The following fields are optional.

	// Logf, if set, is a logging function to use; if unset, logs are
	// dropped.
	Logf logger.Logf

	// DialPlan, if set, contains instructions from the control server on
	// how to connect to it. If present, we will try the methods in this
	// plan before falling back to DNS.
	DialPlan *atomic.Pointer[tailcfg.ControlDialPlan]
}
