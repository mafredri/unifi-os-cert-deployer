package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	liveUniFiURL      = flag.String("url", "", "UniFi console root URL for TestUniFiLiveUpload")
	liveUniFiActivate = flag.Bool("activate", false, "activate the uploaded certificate in TestUniFiLiveUpload")
	liveUniFiInsecure = flag.Bool("insecure", false, "skip TLS verification in TestUniFiLiveUpload")
)

const maxLiveDiagnosticResponseBytes = 64 << 10

func TestSessionCSRFTokenAuthorizesCertificateOperations(t *testing.T) {
	for _, source := range []string{"X-CSRF-Token", "X-Updated-CSRF-Token", "cookie"} {
		t.Run(source, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/auth/login" {
					payload := base64.RawURLEncoding.EncodeToString([]byte(`{"csrfToken":"login-token"}`))
					cookieValue := "opaque-session"
					if source == "cookie" {
						cookieValue = "header." + payload + ".signature"
					}
					http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: cookieValue, Path: "/"})
					if source != "cookie" {
						w.Header().Set(source, "login-token")
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				want := "rotated-token"
				if r.Method == http.MethodPost {
					want = "login-token"
				}
				if r.Header.Get("X-CSRF-Token") != want {
					http.Error(w, "Invalid CSRF Token", http.StatusForbidden)
					return
				}
				if _, err := r.Cookie("TOKEN"); err != nil {
					http.Error(w, "missing session", http.StatusUnauthorized)
					return
				}
				if r.Method == http.MethodPost {
					w.Header().Set("X-CSRF-Token", "login-token")
					w.Header().Set("X-Updated-CSRF-Token", "rotated-token")
					writeTestJSON(t, w, map[string]string{"id": "uploaded"})
					return
				}
				if r.Method == http.MethodGet {
					writeTestJSON(t, w, []UniFiCertificate{})
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			client := mustNewTestUniFiClient(t, server.URL)
			if err := client.Login(t.Context()); err != nil {
				t.Fatal(err)
			}
			id, err := client.UploadCertificate(t.Context(), "test", []byte("cert"), []byte("key"))
			if err != nil {
				t.Fatal(err)
			}
			if err := client.ActivateCertificate(t.Context(), id); err != nil {
				t.Fatal(err)
			}
			if _, err := client.ListCertificates(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := client.DeleteCertificate(t.Context(), id); err != nil {
				t.Fatal(err)
			}
		})
	}
}

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
			t.Errorf(
				"uploaded fields = (%q, %q, %q), want supplied name and bytes unchanged",
				upload.Name,
				upload.Cert,
				upload.Key,
			)
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
			writeTestJSON(t, w, []map[string]any{
				{
					"id":          "expired/id",
					"name":        "service: console old",
					"fingerprint": "CA:BD:2A:79:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
					"valid_to":    "2001-01-01T00:00:00Z",
					"active":      false,
				},
			})
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
	if err != nil {
		t.Fatalf("ListCertificates() error = %v", err)
	}
	if len(certificates) != 1 {
		t.Fatalf("ListCertificates() returned %d certificates, want one", len(certificates))
	}
	if certificates[0].Fingerprint != "CA:BD:2A:79:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF" {
		t.Errorf("fingerprint = %q, want the full API fingerprint", certificates[0].Fingerprint)
	}
	if certificates[0].Name != "service: console old" || certificates[0].Active == nil || *certificates[0].Active {
		t.Fatalf("ListCertificates() = %+v, want the API certificate fields", certificates)
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

func TestLoginHonorsCanceledContext(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := mustNewTestUniFiClient(t, server.URL)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	cancel()

	if err := client.Login(ctx); err == nil {
		t.Fatal("Login succeeded with a canceled context")
	}
	if requests.Load() != 0 {
		t.Fatalf("requests after cancellation = %d, want zero", requests.Load())
	}
}

func TestLoginDoesNotFollowRedirect(t *testing.T) {
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
		client, err := NewUniFiClient(testUniFiConfig(rawURL))
		if err != nil {
			t.Errorf("NewUniFiClient(%q) error = %v, want success", rawURL, err)
			continue
		}
		registerUniFiTransportCleanup(t, client)
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
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		t.Errorf("decode login request: %v", err)
	} else if credentials.Username != "operator" || credentials.Password != "test-password" {
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
		URL:         endpoint,
		Username:    "operator",
		Password:    "test-password",
		HTTPTimeout: time.Second,
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
	registerUniFiTransportCleanup(t, client)
	return client
}

func registerUniFiTransportCleanup(t *testing.T, client *UniFiClient) *http.Transport {
	t.Helper()
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("NewUniFiClient transport has type %T, want *http.Transport", client.http.Transport)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

func TestUniFiLiveUpload(t *testing.T) {
	if strings.TrimSpace(*liveUniFiURL) == "" {
		t.Skip("set --url to run the live UniFi upload diagnostic")
	}
	username, err := secretValue("UNIFI_USERNAME", "UNIFI_USERNAME_FILE")
	if err != nil {
		t.Fatal(err)
	}
	password, err := secretValue("UNIFI_PASSWORD", "UNIFI_PASSWORD_FILE")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		t.Fatal("UNIFI_USERNAME or UNIFI_USERNAME_FILE and UNIFI_PASSWORD or UNIFI_PASSWORD_FILE are required")
	}
	certPEM, keyPEM, err := liveDiagnosticCertificate(*liveUniFiURL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewUniFiClient(UniFiConfig{
		URL:           *liveUniFiURL,
		Username:      username,
		Password:      password,
		HTTPTimeout:   defaultUniFiHTTPTimeout,
		SkipTLSVerify: *liveUniFiInsecure,
	})
	if err != nil {
		t.Fatal(err)
	}
	baseTransport := registerUniFiTransportCleanup(t, client)
	client.http.Transport = &liveDiagnosticTransport{
		base:       baseTransport,
		t:          t,
		redactions: []string{username, password, string(certPEM), string(keyPEM)},
	}
	if err := client.Login(t.Context()); err != nil {
		t.Fatalf("login: %v", err)
	}
	name := "unifi-live-diagnostic-" + time.Now().UTC().Format("20060102T150405Z")
	id, err := client.UploadCertificate(t.Context(), name, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("upload certificate: %v", err)
	}
	t.Logf("live UniFi: uploaded certificate name=%q id=%q", name, id)
	if *liveUniFiActivate {
		if err := client.ActivateCertificate(t.Context(), id); err != nil {
			t.Fatalf("activate certificate: %v", err)
		}
		t.Log("live UniFi: uploaded certificate activated")
	} else {
		t.Log("live UniFi: uploaded certificate remains inactive")
	}
}

func liveDiagnosticCertificate(rawURL string) ([]byte, []byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse diagnostic URL: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, nil, fmt.Errorf("diagnostic URL has no host")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	serial.Add(serial, big.NewInt(1))
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate key: %w", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create diagnostic certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal diagnostic key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	return certPEM, keyPEM, nil
}

type liveDiagnosticTransport struct {
	base       http.RoundTripper
	t          *testing.T
	redactions []string
}

func (d *liveDiagnosticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	d.t.Helper()
	response, err := d.base.RoundTrip(req)
	if err != nil {
		d.t.Logf("live UniFi: %s %s error=%v", req.Method, req.URL.EscapedPath(), err)
		return nil, err
	}
	d.t.Logf(
		"live UniFi: %s %s status=%s request-cookie=%t request-csrf=%t response-set-cookie=%t response-csrf=%t",
		req.Method,
		req.URL.EscapedPath(),
		response.Status,
		req.Header.Get("Cookie") != "",
		req.Header.Get("X-CSRF-Token") != "",
		len(response.Cookies()) > 0,
		response.Header.Get("X-CSRF-Token") != "" || response.Header.Get("X-Updated-CSRF-Token") != "",
	)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		redactions := append([]string{}, d.redactions...)
		redactions = append(
			redactions,
			req.Header.Get("Cookie"),
			req.Header.Get("X-CSRF-Token"),
			response.Header.Get("X-CSRF-Token"),
			response.Header.Get("X-Updated-CSRF-Token"),
		)
		for _, cookie := range append(req.Cookies(), response.Cookies()...) {
			redactions = append(redactions, cookie.Value)
		}
		d.logFailureResponse(response, redactions)
	}
	return response, nil
}

func (d *liveDiagnosticTransport) logFailureResponse(response *http.Response, redactions []string) {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxLiveDiagnosticResponseBytes+1))
	_ = response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		d.t.Logf("live UniFi: read error response: %v", err)
		return
	}
	truncated := len(body) > maxLiveDiagnosticResponseBytes
	if truncated {
		body = body[:maxLiveDiagnosticResponseBytes]
	}
	truncationNotice := ""
	if truncated {
		truncationNotice = " (truncated)"
	}
	d.t.Logf(
		"live UniFi: server error response%s: %s",
		truncationNotice,
		redactLiveDiagnosticBody(body, redactions),
	)
}

func redactLiveDiagnosticBody(body []byte, redactions []string) string {
	text := strings.TrimSpace(string(body))
	var value any
	if json.Unmarshal(body, &value) == nil {
		if encoded, err := json.Marshal(redactLiveDiagnosticJSON(value)); err == nil {
			text = string(encoded)
		}
	}
	for _, secret := range redactions {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[REDACTED]")
		}
	}
	return text
}

func redactLiveDiagnosticJSON(value any) any {
	switch value := value.(type) {
	case []any:
		for index := range value {
			value[index] = redactLiveDiagnosticJSON(value[index])
		}
	case map[string]any:
		for name, nested := range value {
			if isLiveDiagnosticSensitiveField(name) {
				value[name] = "[REDACTED]"
				continue
			}
			value[name] = redactLiveDiagnosticJSON(nested)
		}
	}
	return value
}

func isLiveDiagnosticSensitiveField(name string) bool {
	lowerName := strings.ToLower(name)
	for _, fragment := range []string{
		"password",
		"token",
		"secret",
		"key",
		"cert",
		"cookie",
		"authorization",
	} {
		if strings.Contains(lowerName, fragment) {
			return true
		}
	}
	return false
}
