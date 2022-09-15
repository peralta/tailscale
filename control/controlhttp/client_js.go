// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlhttp

import (
	"context"
	"encoding/base64"
	"net"
	"net/url"

	"nhooyr.io/websocket"
	"tailscale.com/control/controlbase"
)

// Variant of Dial that tunnels the request over WebSockets, since we cannot do
// bi-directional communication over an HTTP connection when in JS.
func Dial(ctx context.Context, opts DialOpts) (*controlbase.Conn, error) {
	init, cont, err := controlbase.ClientDeferred(opts.MachineKey, opts.ControlKey, opts.ProtocolVersion)
	if err != nil {
		return nil, err
	}

	wsScheme := "wss"
	host := opts.Host
	if host == "localhost" {
		wsScheme = "ws"
		host = net.JoinHostPort(host, opts.HTTPPort)
	}
	wsURL := &url.URL{
		Scheme: wsScheme,
		Host:   host,
		Path:   serverUpgradePath,
		// Can't set HTTP headers on the websocket request, so we have to to send
		// the handshake via an HTTP header.
		RawQuery: url.Values{
			handshakeHeaderName: []string{base64.StdEncoding.EncodeToString(init)},
		}.Encode(),
	}
	wsConn, _, err := websocket.Dial(ctx, wsURL.String(), &websocket.DialOptions{
		Subprotocols: []string{upgradeHeaderValue},
	})
	if err != nil {
		return nil, err
	}
	netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
	cbConn, err := cont(ctx, netConn)
	if err != nil {
		netConn.Close()
		return nil, err
	}
	return cbConn, nil
}
