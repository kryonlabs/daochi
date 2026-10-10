// Package native adapts ordinary Go callback result tuples to the typed
// result records used by the Ziran Go foreign-function boundary.
package native

import (
	"context"
	"net"
	"net/http"
)

type DialResult struct {
	Value net.Conn
	Error error
}

func Dial(dialer *net.Dialer, context context.Context, network, address string) DialResult {
	connection, err := dialer.DialContext(context, network, address)
	return DialResult{connection, err}
}

func DialError(result DialResult) error { return result.Error }
func FailedDial(err error) DialResult   { return DialResult{Error: err} }

func InstallDial(transport *http.Transport, callback func(context.Context, string, string) DialResult) {
	transport.DialContext = func(context context.Context, network, address string) (net.Conn, error) {
		result := callback(context, network, address)
		return result.Value, result.Error
	}
}
