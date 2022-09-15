// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/tka"
	"tailscale.com/types/key"
)

var netlockCmd = &ffcli.Command{
	Name:       "lock",
	ShortUsage: "lock <sub-command> <arguments>",
	ShortHelp:  "Manipulate the tailnet key authority",
	Subcommands: []*ffcli.Command{
		nlInitCmd,
		nlStatusCmd,
		nlAddCmd,
		nlRemoveCmd,
	},
	Exec: runNetworkLockStatus,
}

var nlInitCmd = &ffcli.Command{
	Name:       "init",
	ShortUsage: "init <public-key>...",
	ShortHelp:  "Initialize the tailnet key authority",
	Exec:       runNetworkLockInit,
}

func runNetworkLockInit(ctx context.Context, args []string) error {
	st, err := localClient.NetworkLockStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if st.Enabled {
		return errors.New("network-lock is already enabled")
	}

	// Parse the set of initially-trusted keys.
	// Keys are specified using their key.NLPublic.MarshalText representation,
	// with an optional '?<votes>' suffix.
	var keys []tka.Key
	for i, a := range args {
		var key key.NLPublic
		spl := strings.SplitN(a, "?", 2)
		if err := key.UnmarshalText([]byte(spl[0])); err != nil {
			return fmt.Errorf("parsing key %d: %v", i+1, err)
		}

		k := tka.Key{
			Kind:   tka.Key25519,
			Public: key.Verifier(),
			Votes:  1,
		}
		if len(spl) > 1 {
			votes, err := strconv.Atoi(spl[1])
			if err != nil {
				return fmt.Errorf("parsing key %d votes: %v", i+1, err)
			}
			k.Votes = uint(votes)
		}
		keys = append(keys, k)
	}

	status, err := localClient.NetworkLockInit(ctx, keys)
	if err != nil {
		return err
	}

	fmt.Printf("Status: %+v\n\n", status)
	return nil
}

var nlStatusCmd = &ffcli.Command{
	Name:       "status",
	ShortUsage: "status",
	ShortHelp:  "Outputs the state of network lock",
	Exec:       runNetworkLockStatus,
}

func runNetworkLockStatus(ctx context.Context, args []string) error {
	st, err := localClient.NetworkLockStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if st.Enabled {
		fmt.Println("Network-lock is ENABLED.")
	} else {
		fmt.Println("Network-lock is NOT enabled.")
	}
	p, err := st.PublicKey.MarshalText()
	if err != nil {
		return err
	}
	fmt.Printf("our public-key: %s\n", p)
	return nil
}

var nlAddCmd = &ffcli.Command{
	Name:       "add",
	ShortUsage: "add <public-key>...",
	ShortHelp:  "Adds one or more signing keys to the tailnet key authority",
	Exec: func(ctx context.Context, args []string) error {
		return runNetworkLockModify(ctx, args, nil)
	},
}

var nlRemoveCmd = &ffcli.Command{
	Name:       "remove",
	ShortUsage: "remove <public-key>...",
	ShortHelp:  "Removes one or more signing keys to the tailnet key authority",
	Exec: func(ctx context.Context, args []string) error {
		return runNetworkLockModify(ctx, nil, args)
	},
}

func runNetworkLockModify(ctx context.Context, addArgs, removeArgs []string) error {
	st, err := localClient.NetworkLockStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if st.Enabled {
		return errors.New("network-lock is already enabled")
	}

	// Parse the set of initially-trusted keys.
	// Keys are specified using their key.NLPublic.MarshalText representation,
	// with an optional '?<votes>' suffix.
	parseArgs := func(args []string) ([]tka.Key, error) {
		var keys []tka.Key
		for i, a := range addArgs {
			var nlpk key.NLPublic
			spl := strings.SplitN(a, "?", 2)
			if err := nlpk.UnmarshalText([]byte(spl[0])); err != nil {
				return nil, fmt.Errorf("parsing key %d: %v", i+1, err)
			}

			k := tka.Key{
				Kind:   tka.Key25519,
				Public: nlpk.Verifier(),
				Votes:  1,
			}
			if len(spl) > 1 {
				votes, err := strconv.Atoi(spl[1])
				if err != nil {
					return nil, fmt.Errorf("parsing key %d votes: %v", i+1, err)
				}
				k.Votes = uint(votes)
			}
			keys = append(keys, k)
		}
		return keys, nil
	}

	addKeys, err := parseArgs(addArgs)
	if err != nil {
		return err
	}
	removeKeys, err := parseArgs(removeArgs)
	if err != nil {
		return err
	}

	status, err := localClient.NetworkLockModify(ctx, addKeys, removeKeys)
	if err != nil {
		return err
	}

	fmt.Printf("Status: %+v\n\n", status)
	return nil
}
