package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUploadCertificatePostsBytesAndNameWithoutWorkflow(t *testing.T) {
	const certificate = "opaque certificate payload"
	const privateKey = "opaque key payload"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/userCertificates" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		var upload struct {
			Name string `json:"name"`
			Cert string `json:"cert"`
			Key  string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&upload); err != nil {
			t.Errorf("decode upload request: %v", err)
			return
		}
		if upload.Name != "exact operator name" || upload.Cert != certificate || upload.Key != privateKey {
			t.Errorf("uploaded fields = (%q, %q, %q), want supplied name and bytes unchanged", upload.Name, upload.Cert, upload.Key)
		}
		writeTestJSON(t, w, map[string]string{"id": "opaque/id"})
	}))
	defer server.Close()

	client := mustNewTestUniFiClient(t, server.URL)
	id, err := client.UploadCertificate(t.Context(), "exact operator name", []byte(certificate), []byte(privateKey))
	if err != nil || id != "opaque/id" {
		t.Fatalf("UploadCertificate() = (%q, %v), want opaque ID", id, err)
	}
	if requests.Load() != 1 {
		t.Fatalf("UploadCertificate made %d request(s), want only the upload request", requests.Load())
	}
}

func TestActivateCertificateEscapesOpaqueID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.EscapedPath() != "/api/userCertificates/opaque%2Fid/status" {
			t.Errorf("activation request = %s %q", r.Method, r.URL.EscapedPath())
		}
		var status struct {
			Active bool `json:"active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&status); err != nil || !status.Active {
			t.Errorf("activation did not request active=true")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := mustNewTestUniFiClient(t, server.URL)
	if err := client.ActivateCertificate(t.Context(), "opaque/id"); err != nil {
		t.Fatalf("ActivateCertificate() error = %v", err)
	}
}

func TestListAndDeleteCertificates(t *testing.T) {
	var deletedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if r.URL.Path != "/api/userCertificates" {
				t.Errorf("list path = %q", r.URL.Path)
			}
			writeTestJSON(t, w, []map[string]any{{"id": "expired/id", "name": "service: console old", "valid_to": "2001-01-01T00:00:00Z", "active": false}})
		case http.MethodDelete:
			deletedPath = r.URL.EscapedPath()
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := mustNewTestUniFiClient(t, server.URL)
	certificates, err := client.ListCertificates(t.Context())
	if err != nil || len(certificates) != 1 || certificates[0].Name != "service: console old" || certificates[0].Active == nil || *certificates[0].Active {
		t.Fatalf("ListCertificates() = (%+v, %v), want the API certificate fields", certificates, err)
	}
	if err := client.DeleteCertificate(t.Context(), certificates[0].ID); err != nil {
		t.Fatalf("DeleteCertificate() error = %v", err)
	}
	if deletedPath != "/api/userCertificates/expired%2Fid" {
		t.Fatalf("delete path = %q, want opaque ID as one escaped segment", deletedPath)
	}
}

func TestUploadCertificateReturnsAPIRejectionAndMissingID(t *testing.T) {
	for _, test := range []struct {
		name     string
		handler  http.HandlerFunc
		wantText string
	}{
		{
			name: "API rejection",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "private response details", http.StatusBadRequest)
			},
			wantText: "HTTP 400",
		},
		{
			name: "missing ID",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeTestJSON(t, w, map[string]string{"name": "created"})
			},
			wantText: "omitted id",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			client := mustNewTestUniFiClient(t, server.URL)
			_, err := client.UploadCertificate(t.Context(), "name", []byte("cert"), []byte("key"))
			if err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("UploadCertificate() error = %v, want %q", err, test.wantText)
			}
			if strings.Contains(err.Error(), "private response details") {
				t.Fatalf("UploadCertificate() exposed response body: %v", err)
			}
		})
	}
}

func TestLoginHonorsCanceledContextAndDoesNotFollowRedirect(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/api/auth/login" {
			http.Redirect(w, r, "http://127.0.0.1:1/steal", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	client := mustNewTestUniFiClient(t, server.URL)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := client.Login(ctx); err == nil {
		t.Fatal("Login succeeded with a canceled context")
	}
	if requests.Load() != 0 {
		t.Fatalf("requests after cancellation = %d, want zero", requests.Load())
	}
	if err := client.Login(t.Context()); err == nil {
		t.Fatal("Login followed a redirect")
	}
	if requests.Load() != 1 {
		t.Fatalf("login requests = %d, want one without following redirect", requests.Load())
	}
}

func TestLoginHonorsHTTPTimeout(t *testing.T) {
	var loginCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginCalls.Add(1)
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cfg := testUniFiConfig(server.URL)
	cfg.HTTPTimeout = 20 * time.Millisecond
	client := mustNewTestUniFiClientWithConfig(t, cfg)
	if err := client.Login(t.Context()); err == nil {
		t.Fatal("Login succeeded despite an HTTP timeout")
	}
	if loginCalls.Load() != 1 {
		t.Fatalf("login calls = %d, want one timed-out request", loginCalls.Load())
	}
}

func TestLoginVerifiesTLSUnlessExplicitlySkipped(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testUniFiLogin(t, w, r)
	}))
	defer server.Close()

	cfg := testUniFiConfig(server.URL)
	secureClient := mustNewTestUniFiClientWithConfig(t, cfg)
	if err := secureClient.Login(t.Context()); err == nil {
		t.Fatal("Login accepted an untrusted TLS certificate by default")
	}
	cfg.SkipTLSVerify = true
	insecureClient := mustNewTestUniFiClientWithConfig(t, cfg)
	if err := insecureClient.Login(t.Context()); err != nil {
		t.Fatalf("Login failed with explicit TLS verification skip: %v", err)
	}
}

func TestNewUniFiClientValidatesOrigin(t *testing.T) {
	for _, rawURL := range []string{
		"https://console.example.test",
		"http://console.example.test/",
		"HTTP://console.example.test",
	} {
		if _, err := NewUniFiClient(testUniFiConfig(rawURL)); err != nil {
			t.Errorf("NewUniFiClient(%q) error = %v, want success", rawURL, err)
		}
	}

	tests := []struct {
		url       string
		wantError string
	}{
		{url: "relative/path", wantError: "absolute"},
		{url: "https:///missing-host", wantError: "host"},
		{url: "ftp://console.example.test", wantError: "http or https"},
		{url: "https://user:password@console.example.test", wantError: "credentials"},
		{url: "https://console.example.test/api", wantError: "root"},
		{url: "https://console.example.test?token=secret", wantError: "query"},
		{url: "https://console.example.test?", wantError: "query"},
		{url: "https://console.example.test#private", wantError: "fragment"},
		{url: "https://console.example.test#", wantError: "fragment"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			_, err := NewUniFiClient(testUniFiConfig(tt.url))
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("NewUniFiClient(%q) error = %v, want an error containing %q", tt.url, err, tt.wantError)
			}
		})
	}
}

func testUniFiLogin(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()
	if r.URL.Path != "/api/auth/login" {
		return false
	}
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("unexpected login request method or content type")
	}
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil || credentials.Username != "operator" || credentials.Password != "test-password" {
		t.Errorf("login request omitted configured credentials")
	}
	if r.Header.Get("X-CSRF-Token") != "" {
		t.Errorf("login unexpectedly sent a CSRF header")
	}
	http.SetCookie(w, &http.Cookie{Name: "SESSION", Value: "test-session", Path: "/"})
	w.WriteHeader(http.StatusNoContent)
	return true
}

func testUniFiSession(t *testing.T, r *http.Request) error {
	t.Helper()
	if r.Header.Get("Cookie") != "SESSION=test-session" {
		return fmt.Errorf("request did not carry the login session cookie")
	}
	if r.Header.Get("X-CSRF-Token") != "" {
		return fmt.Errorf("request unexpectedly sent a CSRF header")
	}
	return nil
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func testUniFiConfig(endpoint string) UniFiConfig {
	return UniFiConfig{
		URL: endpoint, Username: "operator", Password: "test-password", HTTPTimeout: time.Second,
	}
}

func mustNewTestUniFiClient(t *testing.T, endpoint string) *UniFiClient {
	t.Helper()
	return mustNewTestUniFiClientWithConfig(t, testUniFiConfig(endpoint))
}

func mustNewTestUniFiClientWithConfig(t *testing.T, cfg UniFiConfig) *UniFiClient {
	t.Helper()
	client, err := NewUniFiClient(cfg)
	if err != nil {
		t.Fatalf("NewUniFiClient returned error: %v", err)
	}
	return client
}
