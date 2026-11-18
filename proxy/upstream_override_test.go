package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpstreamAddressUsesConfiguredAddressAndPort(t *testing.T) {
	tests := []struct {
		name   string
		config ServerConfig
		want   string
	}{
		{"bind address and default HTTP port", ServerConfig{scheme: "http", bindAddr: "192.0.2.10"}, "192.0.2.10:80"},
		{"bind address and default HTTPS port", ServerConfig{scheme: "https", bindAddr: "192.0.2.10"}, "192.0.2.10:443"},
		{"configured port only", ServerConfig{scheme: "https", bindAddr: "192.0.2.10", upstreamPort: "8443"}, "192.0.2.10:8443"},
		{"configured address only", ServerConfig{scheme: "http", bindAddr: "192.0.2.10", upstreamAddr: "127.0.0.1"}, "127.0.0.1:80"},
		{"configured address and port", ServerConfig{scheme: "http", bindAddr: "192.0.2.10", upstreamAddr: "127.0.0.1", upstreamPort: "8000"}, "127.0.0.1:8000"},
		{"configured IPv6 address", ServerConfig{scheme: "https", bindAddr: "192.0.2.10", upstreamAddr: "::1", upstreamPort: "8443"}, "[::1]:8443"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := NewServer(&test.config)
			if got := server.upstreamAddress(); got != test.want {
				t.Errorf("upstreamAddress() = %q, want %q", got, test.want)
			}
		})
	}
}

// A backend in the same network namespace that listens on its own ports, such
// as an ingress controller in the same pod, is reached on the configured
// address and port instead of on the bind address.
func TestUpstreamTransportDialsConfiguredAddress(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Host)
	}))
	t.Cleanup(backend.Close)
	host, port, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split backend address: %v", err)
	}

	server := NewServer(&ServerConfig{
		scheme:       "http",
		bindAddr:     "192.0.2.10", // Not on this machine
		upstreamAddr: host,
		upstreamPort: port,
	})
	t.Cleanup(server.closeUpstreamIdleConnections)

	request, err := http.NewRequest(http.MethodGet, "http://shop.example.com/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	response, err := server.upstreamTransport.RoundTrip(request)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer response.Body.Close()

	body, _ := io.ReadAll(response.Body)
	if string(body) != "shop.example.com" {
		t.Errorf("backend saw Host %q, want shop.example.com", body)
	}
}
