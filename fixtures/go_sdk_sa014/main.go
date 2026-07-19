package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type result struct {
	VulnerableStatuses map[string]int `json:"vulnerable_statuses"`
	VulnerableHits     int            `json:"vulnerable_handler_hits"`
	SafeStatuses       map[string]int `json:"safe_statuses"`
	SafeHits           int            `json:"safe_handler_hits"`
}

const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mhai","version":"1"}}}`

func request(handler http.Handler, host, origin string) int {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(initialize))
	req.Host = host
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req = req.WithContext(context.WithValue(
		req.Context(),
		http.LocalAddrContextKey,
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123},
	))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder.Code
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "mhai", Version: "1"}, nil)
	vulnerableHits := 0
	vulnerable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server {
			vulnerableHits++
			return server
		},
		&mcp.StreamableHTTPOptions{
			Stateless:                  true,
			JSONResponse:               true,
			DisableLocalhostProtection: true,
		},
	)

	protection := http.NewCrossOriginProtection()
	if err := protection.AddTrustedOrigin("https://trusted.fixture.invalid"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	safeHits := 0
	safe := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server {
			safeHits++
			return server
		},
		&mcp.StreamableHTTPOptions{
			Stateless:             true,
			JSONResponse:          true,
			CrossOriginProtection: protection,
		},
	)

	output := result{
		VulnerableStatuses: map[string]int{
			"host":   request(vulnerable, "evil.example", "https://trusted.fixture.invalid"),
			"origin": request(vulnerable, "localhost:43123", "https://attacker.fixture.invalid"),
		},
		VulnerableHits: vulnerableHits,
		SafeStatuses: map[string]int{
			"host":        request(safe, "evil.example", "https://trusted.fixture.invalid"),
			"host_port":   request(safe, "evil.example:80", "https://trusted.fixture.invalid"),
			"host_suffix": request(safe, "localhost.evil.example", "https://trusted.fixture.invalid"),
			"origin":      request(safe, "localhost:43123", "https://attacker.fixture.invalid"),
			"valid":       request(safe, "localhost:43123", "https://trusted.fixture.invalid"),
		},
		SafeHits: safeHits,
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
}
