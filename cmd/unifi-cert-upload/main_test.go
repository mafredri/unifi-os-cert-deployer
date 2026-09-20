package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCLIUploadsFileContentsOnce(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	keyPEM := []byte{}
	api := &uploadAPIFixture{wantCert: string(certPEM), wantKey: string(keyPEM)}
	server := httptest.NewServer(api)
	defer server.Close()

	certFile, keyFile := writeCLIInputFiles(t, certPEM, keyPEM)
	setUploadEnvironment(t, server.URL, certFile, keyFile)

	if err := runCLI(context.Background(), nil); err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}
	if api.logins != 1 || api.uploads != 1 || api.activations != 1 {
		t.Errorf("API calls = login:%d upload:%d activate:%d, want one each", api.logins, api.uploads, api.activations)
	}
	if !strings.HasPrefix(api.name, "fixture upload ") {
		t.Errorf("uploaded name = %q, want configured name", api.name)
	}
	if api.certificateLists != 0 {
		t.Errorf("certificate lists = %d with cleanup disabled, want zero", api.certificateLists)
	}
}

func TestRunCLILogsOperationsWithoutSecrets(t *testing.T) {
	for _, tt := range []struct {
		name           string
		cleanup        bool
		rejectUpload   bool
		wantMessages   []string
		absentMessages []string
	}{
		{
			name: "deployment with cleanup", cleanup: true,
			wantMessages: []string{"Logging in to UniFi", "Logged in to UniFi", "csrf_token_available=true", "Uploading certificate", "Certificate uploaded", "Activating certificate", "Certificate activated", "Expired certificate deleted", "Certificate cleanup completed", "deleted=1"},
		},
		{
			name:           "deployment without cleanup",
			wantMessages:   []string{"Certificate uploaded", "Certificate activated"},
			absentMessages: []string{"Checking expired certificates"},
		},
		{
			name: "upload rejected", cleanup: true, rejectUpload: true,
			wantMessages:   []string{"Uploading certificate", "Certificate operation failed", "operation=upload", "409 Conflict"},
			absentMessages: []string{"Certificate uploaded", "Activating certificate", "Checking expired certificates"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			previousLogger := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
			t.Cleanup(func() { slog.SetDefault(previousLogger) })
			certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
			keyPEM := []byte("private-key-secret-marker")
			api := &uploadAPIFixture{
				wantCert: string(certPEM), wantKey: string(keyPEM),
				cleanupName: "fixture [prod]", rejectDuplicate: tt.rejectUpload,
				name: "fixture [prod] cabd2a79",
			}
			server := httptest.NewServer(api)
			defer server.Close()
			certFile, keyFile := writeCLIInputFiles(t, certPEM, keyPEM)
			setUploadEnvironment(t, server.URL, certFile, keyFile)
			t.Setenv("UNIFI_CERT_NAME", "fixture [prod]")
			if tt.cleanup {
				t.Setenv("UNIFI_CLEANUP", "true")
			}

			err := runCLI(context.Background(), nil)
			if (err != nil) != tt.rejectUpload {
				t.Fatalf("runCLI() error = %v, want failure %t", err, tt.rejectUpload)
			}
			logs := output.String()
			for _, message := range append(tt.wantMessages, "target="+server.URL) {
				if !strings.Contains(logs, message) {
					t.Errorf("logs missing %q: %s", message, logs)
				}
			}
			for _, message := range tt.absentMessages {
				if strings.Contains(logs, message) {
					t.Errorf("logs contain unexpected %q: %s", message, logs)
				}
			}
			wantErrors := 0
			if tt.rejectUpload {
				wantErrors = 1
			}
			if count := strings.Count(logs, "level=ERROR"); count != wantErrors {
				t.Errorf("error log count = %d, want %d", count, wantErrors)
			}
			for _, secret := range []string{"admin", "console-password", string(keyPEM), strings.Split(string(certPEM), "\n")[1], "unifi-session", "csrf-secret-marker", "fixture response body"} {
				if strings.Contains(logs, secret) {
					t.Error("logs expose a credential, payload, or response body")
				}
			}
		})
	}
}

func TestRunCLIUsesLiteralNameAndCertificateFingerprint(t *testing.T) {
	first := readCertificateFixture(t, "isrg-root-x1.pem")
	second := readCertificateFixture(t, "isrg-root-x2.pem")
	// Expected fingerprints: openssl x509 -in testdata/isrg-root-x1.pem -noout -fingerprint -sha1
	tests := []struct {
		name        string
		certificate string
		fingerprint string
	}{
		{name: "ISRG Root X1", certificate: string(first), fingerprint: "cabd2a79"},
		{name: "same DER with CRLF", certificate: strings.ReplaceAll(string(first), "\n", "\r\n"), fingerprint: "cabd2a79"},
		{name: "first certificate in bundle", certificate: string(first) + string(second), fingerprint: "cabd2a79"},
		{name: "ISRG Root X2", certificate: string(second), fingerprint: "bdb1b93c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &uploadAPIFixture{wantCert: tt.certificate, wantKey: "key"}
			server := httptest.NewServer(api)
			defer server.Close()
			certFile, keyFile := writeCLIInputFiles(t, []byte(tt.certificate), []byte("key"))
			setUploadEnvironment(t, server.URL, certFile, keyFile)
			const baseName = " service: $host + [prod] 100% "
			t.Setenv("UNIFI_CERT_NAME", baseName)

			if err := runCLI(context.Background(), nil); err != nil {
				t.Fatalf("runCLI() error = %v", err)
			}
			if want := baseName + " " + tt.fingerprint; api.name != want {
				t.Errorf("uploaded name = %q, want %q", api.name, want)
			}
		})
	}
}

func TestRunCLIRejectsInvalidCertificatePEMBeforeRequests(t *testing.T) {
	for _, certificate := range []string{
		"not PEM",
		"-----BEGIN CERTIFICATE-----\ninvalid!\n-----END CERTIFICATE-----\n",
		"-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
	} {
		api := &uploadAPIFixture{}
		server := httptest.NewServer(api)
		defer server.Close()
		certFile, keyFile := writeCLIInputFiles(t, []byte(certificate), nil)
		setUploadEnvironment(t, server.URL, certFile, keyFile)

		err := runCLI(context.Background(), nil)
		if err == nil || !strings.Contains(err.Error(), "expected a PEM CERTIFICATE block") {
			t.Fatalf("runCLI() error = %v, want certificate PEM error", err)
		}
		if api.logins != 0 || api.uploads != 0 || api.activations != 0 || api.certificateLists != 0 {
			t.Errorf("API calls after PEM error = login:%d upload:%d activate:%d list:%d, want none", api.logins, api.uploads, api.activations, api.certificateLists)
		}
	}
}

func TestRunCLICleanupUsesLiteralNameAsScope(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	api := &uploadAPIFixture{wantCert: string(certPEM), wantKey: "key"}
	server := httptest.NewServer(api)
	defer server.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("key"))
	setUploadEnvironment(t, server.URL, certFile, keyFile)
	const baseName = "service: $host + [prod] 100%"
	t.Setenv("UNIFI_CERT_NAME", baseName)
	t.Setenv("UNIFI_CLEANUP", "true")
	api.cleanupName = baseName

	if err := runCLI(context.Background(), nil); err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}
	if api.certificateLists != 1 {
		t.Fatalf("certificate lists = %d, want one with cleanup enabled", api.certificateLists)
	}
	want := []string{"/api/userCertificates/expired%2Fmatch"}
	if fmt.Sprint(api.deletions) != fmt.Sprint(want) {
		t.Fatalf("deleted certificate paths = %q, want only configured-name expired inactive match %q", api.deletions, want)
	}
}

func TestRunCLIReturnsDuplicateRejectionWithoutRetry(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	api := &uploadAPIFixture{rejectDuplicate: true, wantCert: string(certPEM), wantKey: "opaque key"}
	server := httptest.NewServer(api)
	defer server.Close()

	certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("opaque key"))
	setUploadEnvironment(t, server.URL, certFile, keyFile)
	if err := runCLI(context.Background(), nil); err != nil {
		t.Fatalf("initial runCLI() error = %v", err)
	}
	t.Setenv("UNIFI_CLEANUP", "true")

	err := runCLI(context.Background(), nil)
	if err == nil {
		t.Fatal("runCLI() error = nil, want duplicate upload rejection")
	}
	if api.logins != 2 || api.uploads != 2 || api.activations != 1 {
		t.Errorf("API calls after rejection = login:%d upload:%d activate:%d, want 2,2,1", api.logins, api.uploads, api.activations)
	}
	if api.certificateLists != 0 {
		t.Errorf("cleanup ran after upload rejection, with %d certificate list request(s)", api.certificateLists)
	}
	if strings.Contains(err.Error(), "fixture response body") {
		t.Errorf("runCLI() exposed the API response body: %v", err)
	}
}

func TestRunCLIDoesNotCleanUpWhenActivationFails(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	api := &uploadAPIFixture{rejectActivation: true, wantCert: string(certPEM), wantKey: "key"}
	server := httptest.NewServer(api)
	defer server.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("key"))
	setUploadEnvironment(t, server.URL, certFile, keyFile)
	t.Setenv("UNIFI_CLEANUP", "true")

	if err := runCLI(context.Background(), nil); err == nil {
		t.Fatal("runCLI() succeeded despite activation rejection")
	}
	if api.uploads != 1 || api.activations != 1 {
		t.Fatalf("API calls before activation failure = upload:%d activate:%d, want one each", api.uploads, api.activations)
	}
	if api.certificateLists != 0 {
		t.Fatalf("cleanup ran after activation rejection, with %d certificate list request(s)", api.certificateLists)
	}
}

func TestRunCLIReadsFilesBeforeMakingRequests(t *testing.T) {
	api := &uploadAPIFixture{}
	server := httptest.NewServer(api)
	defer server.Close()
	setUploadEnvironment(t, server.URL, filepath.Join(t.TempDir(), "missing.crt"), filepath.Join(t.TempDir(), "missing.key"))

	err := runCLI(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "read certificate") {
		t.Fatalf("runCLI() error = %v, want certificate read error", err)
	}
	if api.logins != 0 || api.uploads != 0 || api.activations != 0 {
		t.Errorf("API calls after file read failure = login:%d upload:%d activate:%d, want none", api.logins, api.uploads, api.activations)
	}
}

func TestRunCLIHelpWorksWithoutCredentialsOrFiles(t *testing.T) {
	for _, name := range []string{
		"UNIFI_URL", "UNIFI_USERNAME", "UNIFI_USERNAME_FILE", "UNIFI_PASSWORD", "UNIFI_PASSWORD_FILE",
		"LEGO_HOOK_CERT_PATH", "LEGO_HOOK_CERT_KEY_PATH",
	} {
		t.Setenv(name, "")
	}
	if err := runCLI(context.Background(), []string{"--help"}); err != nil {
		t.Fatalf("runCLI(--help) error = %v, want nil without configuration", err)
	}
}

func readCertificateFixture(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read certificate fixture: %v", err)
	}
	return contents
}

func writeCLIInputFiles(t *testing.T, certPEM, keyPEM []byte) (string, string) {
	t.Helper()
	directory := t.TempDir()
	certFile := filepath.Join(directory, "cert.pem")
	keyFile := filepath.Join(directory, "key.pem")
	for path, contents := range map[string][]byte{certFile: certPEM, keyFile: keyPEM} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}
	return certFile, keyFile
}

func setUploadEnvironment(t *testing.T, serverURL, certFile, keyFile string) {
	t.Helper()
	for name, value := range map[string]string{
		"UNIFI_URL":               serverURL,
		"UNIFI_USERNAME":          "admin",
		"UNIFI_USERNAME_FILE":     "",
		"UNIFI_PASSWORD":          "console-password",
		"UNIFI_PASSWORD_FILE":     "",
		"UNIFI_HTTP_TIMEOUT":      "",
		"UNIFI_SKIP_TLS_VERIFY":   "",
		"UNIFI_CLEANUP":           "false",
		"UNIFI_CERT_FILE":         "",
		"UNIFI_KEY_FILE":          "",
		"LEGO_HOOK_CERT_PATH":     certFile,
		"LEGO_HOOK_CERT_KEY_PATH": keyFile,
		"RENEWED_LINEAGE":         "",
		"UNIFI_CERT_NAME":         "fixture upload",
	} {
		t.Setenv(name, value)
	}
}

type uploadAPIFixture struct {
	logins           int
	uploads          int
	activations      int
	certificateLists int
	rejectDuplicate  bool
	rejectActivation bool
	wantCert         string
	wantKey          string
	name             string
	cleanupName      string
	deletions        []string
}

func (api *uploadAPIFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/auth/login" {
		if cookie, err := r.Cookie("unifi-session"); err != nil || cookie.Value != "accepted" {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
	}

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/login":
		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
			http.Error(w, "invalid login body", http.StatusBadRequest)
			return
		}
		if credentials.Username != "admin" || credentials.Password != "console-password" {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		api.logins++
		w.Header().Set("X-CSRF-Token", "csrf-secret-marker")
		http.SetCookie(w, &http.Cookie{Name: "unifi-session", Value: "accepted", Path: "/"})
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPost && r.URL.Path == "/api/userCertificates":
		api.uploads++
		var upload struct {
			Name string `json:"name"`
			Cert string `json:"cert"`
			Key  string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&upload); err != nil {
			http.Error(w, "invalid upload body", http.StatusBadRequest)
			return
		}
		if upload.Cert != api.wantCert || upload.Key != api.wantKey {
			http.Error(w, "file bytes changed before upload", http.StatusBadRequest)
			return
		}
		if api.rejectDuplicate && upload.Name == api.name {
			http.Error(w, "fixture response body", http.StatusConflict)
			return
		}
		api.name = upload.Name
		writeFixtureJSON(w, map[string]string{"id": fmt.Sprintf("fixture/id-%d", api.uploads)})

	case r.Method == http.MethodPut && strings.HasSuffix(r.URL.EscapedPath(), "/status"):
		api.activations++
		var status struct {
			Active bool `json:"active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&status); err != nil || !status.Active {
			http.Error(w, "expected activation", http.StatusBadRequest)
			return
		}
		if api.rejectActivation {
			http.Error(w, "activation rejected", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && r.URL.Path == "/api/userCertificates":
		api.certificateLists++
		baseName := api.cleanupName
		writeFixtureJSON(w, []map[string]any{
			{"id": "expired/match", "name": baseName + " old", "valid_to": "2001-01-01T00:00:00Z", "active": false},
			{"id": "expired/regex-neighbor", "name": strings.Replace(baseName, "[prod]", "xprod]", 1) + " old", "valid_to": "2001-01-01T00:00:00Z", "active": false},
			{"id": "expired/no-suffix", "name": baseName + " ", "valid_to": "2001-01-01T00:00:00Z", "active": false},
			{"id": "expired/active", "name": baseName + " active", "valid_to": "2001-01-01T00:00:00Z", "active": true},
			{"id": "future/inactive", "name": baseName + " future", "valid_to": "2999-01-01T00:00:00Z", "active": false},
			{"id": "invalid/expiry", "name": baseName + " invalid", "valid_to": "bad-date", "active": false},
			{"id": "unmanaged", "name": "other service old", "valid_to": "2001-01-01T00:00:00Z", "active": false},
			{"id": "unknown/active", "name": baseName + " unknown", "valid_to": "2001-01-01T00:00:00Z"},
		})

	case r.Method == http.MethodDelete:
		api.deletions = append(api.deletions, r.URL.EscapedPath())
		w.WriteHeader(http.StatusNoContent)

	default:
		http.NotFound(w, r)
	}
}

func writeFixtureJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
