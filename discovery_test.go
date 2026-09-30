package main

import (
	"reflect"
	"testing"
)

func TestLANDiscoveryMetadataContainsIdentityButNoTrustSecret(t *testing.T) {
	nodeID := "0123456789abcdef"
	if got := Discovery_InstanceName("Home", nodeID); got != "Home 0123456789ab" {
		t.Fatalf("instance name = %q", got)
	}
	want := []string{
		"id=" + nodeID,
		"protocol=6",
		"trust=pairing-required",
		"path=/api/v1/node",
	}
	if got := Discovery_Text(nodeID); !reflect.DeepEqual(got, want) {
		t.Fatalf("discovery text = %#v, want %#v", got, want)
	}
}

func TestListenerPort(t *testing.T) {
	parsed := Discovery_ListenerPort("0.0.0.0:8080")
	port, err := parsed.Value, parsed.Error
	if err != nil {
		t.Fatal(err)
	}
	if port != 8080 {
		t.Fatalf("port = %d, want 8080", port)
	}
}
