// Original discovery from 8f38545, with only the native resource calls injected for tests.
package main

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/grandcat/zeroconf"
)

const (
	baselineDiscoveryService = "_daochi._tcp"
	baselineDiscoveryDomain  = "local."
)

func (s *Server) baselineRunLANDiscovery(ctx context.Context, register func(string, string, string, int, []string, []net.Interface) (*zeroconf.Server, error), shutdown func(*zeroconf.Server)) {
	if !s.cfg.LANDiscovery {
		return
	}
	port, err := baselineListenerPort(s.cfg.Addr)
	if err != nil {
		slog.Warn("LAN discovery disabled", "error", err)
		return
	}
	server, err := register(
		baselineDiscoveryInstanceName(s.cfg.NodeDisplayName, s.node.ID),
		baselineDiscoveryService,
		baselineDiscoveryDomain,
		port,
		baselineDiscoveryText(s.node.ID),
		nil,
	)
	if err != nil {
		slog.Warn("LAN discovery unavailable", "error", err)
		return
	}
	slog.Info("advertising Daochi node on LAN", "node_id", s.node.ID, "port", port)
	defer shutdown(server)
	<-ctx.Done()
}

func baselineListenerPort(address string) (int, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(portText)
}

func baselineDiscoveryInstanceName(displayName, nodeID string) string {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = "Daochi Node"
	}
	if len(nodeID) > 12 {
		nodeID = nodeID[:12]
	}
	return displayName + " " + nodeID
}

func baselineDiscoveryText(nodeID string) []string {
	return []string{
		"id=" + nodeID,
		"protocol=6",
		"trust=pairing-required",
		"path=/api/v1/node",
	}
}
