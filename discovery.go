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
	discoveryService = "_daochi._tcp"
	discoveryDomain  = "local."
)

func (s *Server) runLANDiscovery(ctx context.Context) {
	if !s.cfg.LANDiscovery {
		return
	}
	port, err := listenerPort(s.cfg.Addr)
	if err != nil {
		slog.Warn("LAN discovery disabled", "error", err)
		return
	}
	server, err := zeroconf.Register(
		discoveryInstanceName(s.cfg.NodeDisplayName, s.node.ID),
		discoveryService,
		discoveryDomain,
		port,
		discoveryText(s.node.ID),
		nil,
	)
	if err != nil {
		slog.Warn("LAN discovery unavailable", "error", err)
		return
	}
	slog.Info("advertising Daochi node on LAN", "node_id", s.node.ID, "port", port)
	defer server.Shutdown()
	<-ctx.Done()
}

func listenerPort(address string) (int, error) {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(portText)
}

func discoveryInstanceName(displayName, nodeID string) string {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = "Daochi Node"
	}
	if len(nodeID) > 12 {
		nodeID = nodeID[:12]
	}
	return displayName + " " + nodeID
}

func discoveryText(nodeID string) []string {
	return []string{
		"id=" + nodeID,
		"protocol=6",
		"trust=pairing-required",
		"path=/api/v1/node",
	}
}
