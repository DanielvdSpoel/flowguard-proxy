package cmd

import "testing"

func TestValidateUpstreamFlags(t *testing.T) {
	tests := []struct {
		name      string
		address   string
		httpPort  string
		httpsPort string
		wantError bool
	}{
		{name: "defaults"},
		{name: "loopback with ports", address: "127.0.0.1", httpPort: "8000", httpsPort: "8443"},
		{name: "IPv6 address", address: "::1"},
		{name: "hostname", address: "localhost", wantError: true},
		{name: "address with port", address: "127.0.0.1:8000", wantError: true},
		{name: "port out of range", httpPort: "70000", wantError: true},
		{name: "port zero", httpsPort: "0", wantError: true},
		{name: "port name", httpsPort: "websecure", wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstreamAddress, upstreamHTTPPort, upstreamHTTPSPort = test.address, test.httpPort, test.httpsPort
			t.Cleanup(func() { upstreamAddress, upstreamHTTPPort, upstreamHTTPSPort = "", "", "" })

			if err := validateUpstreamFlags(); (err != nil) != test.wantError {
				t.Errorf("validateUpstreamFlags() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}
