// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Modification: Copy github.com/DataDog/datadog-agent/pkg/network/testutil.RunCommands to here
// to remove the dependency on it.

//go:build linux
// +build linux

package testutil

import (
	"os/exec"
	"strings"
	"testing"
)

// SetupDNAT sets up a NAT translation from:
// * 2.2.2.2 to 1.1.1.1 (OUTPUT Chain)
// * 3.3.3.3 to 1.1.1.1 (PREROUTING Chain)
func SetupDNAT(t *testing.T) {
	cmds := []string{
		"ip link add dummy1 type dummy",
		"ip address add 1.1.1.1 broadcast + dev dummy1",
		"ip link set dummy1 up",
		"iptables -t nat -A OUTPUT --dest 2.2.2.2 -j DNAT --to-destination 1.1.1.1",
		"iptables -t nat -A PREROUTING --dest 3.3.3.3 -j DNAT --to-destination 1.1.1.1",
	}
	RunCommands(t, cmds, false)
}

// TeardownDNAT cleans up the resources created by SetupDNAT
func TeardownDNAT(t *testing.T) {
	cmds := []string{
		// tear down the testing interface, and iptables rule
		"ip link del dummy1",
		"iptables -t nat -D OUTPUT -d 2.2.2.2 -j DNAT --to-destination 1.1.1.1",
		"iptables -t nat -D PREROUTING -d 3.3.3.3 -j DNAT --to-destination 1.1.1.1",

		// clear out the conntrack table
		"conntrack -F",
	}
	RunCommands(t, cmds, true)
}

func getDefaultInterfaceName(t *testing.T) string {
	out := RunCommands(t, []string{"ip route get 8.8.8.8"}, false)
	if len(out) > 0 {
		parts := strings.Split(out[0], " ")
		if len(parts) > 5 {
			return parts[4]
		}
	}
	return ""
}

// SetupDNAT6 sets up a NAT translation from fd00::2 to fd00::1
func SetupDNAT6(t *testing.T) {
	ifName := getDefaultInterfaceName(t)
	cmds := []string{
		"ip link add dummy1 type dummy",
		"ip address add fd00::1 dev dummy1",
		"ip link set dummy1 up",
		"ip -6 route add fd00::2 dev " + ifName,
		"ip6tables -t nat -A OUTPUT --dest fd00::2 -j DNAT --to-destination fd00::1",
	}
	RunCommands(t, cmds, false)
}

// TeardownDNAT6 cleans up the resources created by SetupDNAT6
func TeardownDNAT6(t *testing.T) {
	ifName := getDefaultInterfaceName(t)
	cmds := []string{
		// tear down the testing interface, and iptables rule
		"ip link del dummy1",
		"ip6tables -t nat -D OUTPUT --dest fd00::2 -j DNAT --to-destination fd00::1",

		"ip -6 r del fd00::2 dev " + ifName,

		// clear out the conntrack table
		"conntrack -F",
	}
	RunCommands(t, cmds, true)
}

// SetupVethPair sets up a network namespace, named "test", along with two IP addresses
// 2.2.2.3 and 2.2.2.4 to be used for namespace aware tests.
// 2.2.2.4 is within the "test" namespace, while 2.2.2.3 is a peer in the root namespace.
func SetupVethPair(t *testing.T) {
	cmds := []string{
		"ip netns add test",
		"ip link add veth1 type veth peer name veth2",
		"ip link set veth2 netns test",
		"ip address add 2.2.2.3/24 dev veth1",
		"ip -n test address add 2.2.2.4/24 dev veth2",
		"ip link set veth1 up",
		"ip -n test link set veth2 up",
		"ip netns exec test ip route add default via 2.2.2.3",
	}
	RunCommands(t, cmds, false)
}

// TeardownVethPair cleans up the resources created by SetupVethPair
func TeardownVethPair(t *testing.T) {
	cmds := []string{
		"ip link del veth1",
		"ip -n test link del veth2",
		"ip netns del test",
	}
	RunCommands(t, cmds, true)
}

// SetupCrossNsDNAT sets up a network namespace, named "test", a veth pair, and a NAT
// rule in the "test" network namespace
func SetupCrossNsDNAT(t *testing.T) {
	SetupVethPair(t)

	cmds := []string{
		//this is required to enable conntrack in the root net namespace
		//conntrack won't be enabled unless there is at least one iptables
		//rule that uses connection tracking
		"iptables -I INPUT 1 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT",

		"ip netns exec test iptables -A PREROUTING -t nat -p tcp --dport 80 -j REDIRECT --to-port 8080",
		"ip netns exec test iptables -A PREROUTING -t nat -p udp --dport 80 -j REDIRECT --to-port 8080",
	}
	RunCommands(t, cmds, false)
}

// TeardownCrossNsDNAT cleans up the resources created by SetupCrossNsDNAT
func TeardownCrossNsDNAT(t *testing.T) {
	TeardownVethPair(t)

	cmds := []string{
		"iptables -D INPUT 1",

		"conntrack -F",
	}
	RunCommands(t, cmds, true)
}

// RunCommands runs each command in cmds individually and returns the output
// as a []string, with each element corresponding to the respective command.
// If ignoreErrors is true, it will fail the test via t.Fatal immediately upon error.
// Otherwise, the output on errors will be logged via t.Log.
func RunCommands(t *testing.T, cmds []string, ignoreErrors bool) []string {
	t.Helper()
	var output []string

	for _, c := range cmds {
		args := strings.Split(c, " ")
		c := exec.Command(args[0], args[1:]...)
		out, err := c.CombinedOutput()
		output = append(output, string(out))
		if err != nil && !ignoreErrors {
			t.Fatalf("%s returned %s: %s", c, err, out)
			return nil
		}
	}
	return output
}
