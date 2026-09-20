package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setValidConfigEnvironment(t *testing.T) {
	t.Helper()
	for name, value := range map[string]string{
		"UNIFI_URL":               "http://console.local",
		"UNIFI_USERNAME":          "admin",
		"UNIFI_USERNAME_FILE":     "",
		"UNIFI_PASSWORD":          "console-password",
		"UNIFI_PASSWORD_FILE":     "",
		"UNIFI_HTTP_TIMEOUT":      "",
		"UNIFI_SKIP_TLS_VERIFY":   "",
		"UNIFI_CLEANUP":           "",
		"UNIFI_CERT_FILE":         "",
		"UNIFI_KEY_FILE":          "",
		"LEGO_HOOK_CERT_PATH":     "/lego/certificates/example.crt",
		"LEGO_HOOK_CERT_KEY_PATH": "/lego/certificates/example.key",
		"RENEWED_LINEAGE":         "",
		"UNIFI_CERT_NAME":         "",
	} {
		t.Setenv(name, value)
	}
}

func TestLoadConfigUsesHookEnvironmentAndUniFiDefaults(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("RENEWED_LINEAGE", "/certbot/live/console")

	got, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if got.CertFile != "/lego/certificates/example.crt" || got.KeyFile != "/lego/certificates/example.key" {
		t.Errorf("certificate paths = (%q, %q), want the paths from lego hook environment", got.CertFile, got.KeyFile)
	}
	if got.Name != "unifi-os-le-cert-deployer" || got.Cleanup {
		t.Errorf("name/cleanup = (%q, %t), want default name and disabled cleanup", got.Name, got.Cleanup)
	}
	if got.UniFi.URL != "http://console.local" || got.UniFi.Username != "admin" || got.UniFi.Password != "console-password" {
		t.Errorf("UniFi settings not loaded correctly: URL=%q username=%q", got.UniFi.URL, got.UniFi.Username)
	}
	if got.UniFi.HTTPTimeout != 30*time.Second || got.UniFi.SkipTLSVerify {
		t.Errorf("UniFi HTTP settings = (%s, %t), want (30s, false)", got.UniFi.HTTPTimeout, got.UniFi.SkipTLSVerify)
	}
}

func TestLoadConfigFlagsOverrideHookEnvironment(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("LEGO_HOOK_CERT_PATH", "/hook/cert.pem")
	t.Setenv("LEGO_HOOK_CERT_KEY_PATH", "/hook/key.pem")
	t.Setenv("UNIFI_CERT_FILE", "/own/cert.pem")
	t.Setenv("UNIFI_KEY_FILE", "/own/key.pem")
	t.Setenv("UNIFI_CERT_NAME", "environment-name")
	t.Setenv("UNIFI_CLEANUP", "true")

	got, err := LoadConfig([]string{
		"--cert", "/cli/cert.pem",
		"--key=/cli/key.pem",
		"--name", "cli-name: $host 100%",
		"--cleanup=false",
	})
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if got.CertFile != "/cli/cert.pem" || got.KeyFile != "/cli/key.pem" {
		t.Errorf("certificate paths = (%q, %q), want CLI paths", got.CertFile, got.KeyFile)
	}
	if got.Name != "cli-name: $host 100%" || got.Cleanup {
		t.Errorf("name/cleanup = (%q, %t), want literal CLI name and cleanup override", got.Name, got.Cleanup)
	}
}

func TestLoadConfigPrefersUniFiFilesOverLegoPaths(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_CERT_FILE", "/own/cert.pem")
	t.Setenv("UNIFI_KEY_FILE", "/own/key.pem")
	t.Setenv("RENEWED_LINEAGE", "/certbot/live/console")

	got, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if got.CertFile != "/own/cert.pem" || got.KeyFile != "/own/key.pem" {
		t.Fatalf("certificate paths = (%q, %q), want UniFi-specific paths", got.CertFile, got.KeyFile)
	}
}

func TestLoadConfigUsesCertbotPathsWhenOtherSourcesAreAbsent(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("LEGO_HOOK_CERT_PATH", "")
	t.Setenv("LEGO_HOOK_CERT_KEY_PATH", "")
	t.Setenv("RENEWED_LINEAGE", filepath.Join("/etc/letsencrypt", "live", "console"))

	got, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	wantCert := filepath.Join("/etc/letsencrypt", "live", "console", "cert.pem")
	wantKey := filepath.Join("/etc/letsencrypt", "live", "console", "privkey.pem")
	if got.CertFile != wantCert || got.KeyFile != wantKey {
		t.Fatalf("certificate paths = (%q, %q), want Certbot paths (%q, %q)", got.CertFile, got.KeyFile, wantCert, wantKey)
	}
}

func TestLoadConfigDoesNotMixPartialEnvironmentPairs(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T)
		args    []string
		cert    string
		key     string
		wantErr bool
	}{
		{
			name: "partial UniFi pair blocks lego fallback but flag fills key",
			setup: func(t *testing.T) {
				t.Setenv("UNIFI_CERT_FILE", "/own/cert.pem")
				t.Setenv("UNIFI_KEY_FILE", "")
			},
			args: []string{"--key", "/cli/key.pem"}, cert: "/own/cert.pem", key: "/cli/key.pem",
		},
		{
			name: "partial UniFi pair does not borrow lego key",
			setup: func(t *testing.T) {
				t.Setenv("UNIFI_CERT_FILE", "/own/cert.pem")
				t.Setenv("UNIFI_KEY_FILE", "")
			},
			wantErr: true,
		},
		{
			name: "partial lego pair blocks Certbot fallback",
			setup: func(t *testing.T) {
				t.Setenv("UNIFI_CERT_FILE", "")
				t.Setenv("UNIFI_KEY_FILE", "")
				t.Setenv("LEGO_HOOK_CERT_PATH", "/lego/cert.pem")
				t.Setenv("LEGO_HOOK_CERT_KEY_PATH", "")
				t.Setenv("RENEWED_LINEAGE", "/certbot/live/console")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidConfigEnvironment(t)
			tt.setup(t)
			got, err := LoadConfig(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("LoadConfig() succeeded with an incomplete selected certificate pair")
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig() error = %v", err)
			}
			if got.CertFile != tt.cert || got.KeyFile != tt.key {
				t.Fatalf("certificate paths = (%q, %q), want (%q, %q)", got.CertFile, got.KeyFile, tt.cert, tt.key)
			}
		})
	}
}

func TestLoadConfigUsesCleanupEnvironmentAndFlag(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_CLEANUP", "true")
	got, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if !got.Cleanup {
		t.Fatal("LoadConfig() ignored UNIFI_CLEANUP=true")
	}

	setValidConfigEnvironment(t)
	got, err = LoadConfig([]string{"--cleanup"})
	if err != nil {
		t.Fatalf("LoadConfig(--cleanup) error = %v", err)
	}
	if !got.Cleanup {
		t.Fatal("LoadConfig(--cleanup) did not enable cleanup")
	}
}

func TestLoadConfigReadsUniFiSecretFilesAndTrimsOnlyLineEndings(t *testing.T) {
	setValidConfigEnvironment(t)
	secretDir := t.TempDir()
	usernameFile := filepath.Join(secretDir, "username")
	passwordFile := filepath.Join(secretDir, "password")
	for path, contents := range map[string]string{
		usernameFile: "file-admin\r\n",
		passwordFile: "file-password \n",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}
	t.Setenv("UNIFI_USERNAME", "")
	t.Setenv("UNIFI_USERNAME_FILE", usernameFile)
	t.Setenv("UNIFI_PASSWORD", "")
	t.Setenv("UNIFI_PASSWORD_FILE", passwordFile)

	got, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if got.UniFi.Username != "file-admin" || got.UniFi.Password != "file-password " {
		t.Errorf("UniFi credentials = (%q, %q), want file contents with only line endings removed", got.UniFi.Username, got.UniFi.Password)
	}
}

func TestLoadConfigRequiresUniFiAndCertificatePaths(t *testing.T) {
	tests := []struct {
		name   string
		unset  string
		second string
	}{
		{name: "UniFi URL", unset: "UNIFI_URL"},
		{name: "UniFi username", unset: "UNIFI_USERNAME", second: "UNIFI_USERNAME_FILE"},
		{name: "UniFi password", unset: "UNIFI_PASSWORD", second: "UNIFI_PASSWORD_FILE"},
		{name: "certificate path", unset: "LEGO_HOOK_CERT_PATH"},
		{name: "private key path", unset: "LEGO_HOOK_CERT_KEY_PATH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidConfigEnvironment(t)
			t.Setenv(tt.unset, "")
			if tt.second != "" {
				t.Setenv(tt.second, "")
			}
			if _, err := LoadConfig(nil); err == nil {
				t.Fatalf("LoadConfig() error = nil, want missing %s to fail", tt.name)
			}
		})
	}
}

func TestLoadConfigRejectsConflictingSecretSourcesWithoutLeakingValues(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_USERNAME", "username-secret-marker")
	t.Setenv("UNIFI_USERNAME_FILE", filepath.Join(t.TempDir(), "unused-secret-file"))

	_, err := LoadConfig(nil)
	if err == nil {
		t.Fatal("LoadConfig() error = nil, want direct/file conflict")
	}
	if strings.Contains(err.Error(), "username-secret-marker") {
		t.Errorf("LoadConfig() error exposes secret value: %v", err)
	}
	if !strings.Contains(err.Error(), "UNIFI_USERNAME") || !strings.Contains(err.Error(), "UNIFI_USERNAME_FILE") {
		t.Errorf("LoadConfig() error = %q, want both variable names", err)
	}
}

func TestLoadConfigValidatesUniFiURLTimeoutAndTLSSettings(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_URL", "http://127.0.0.1:8443")
	t.Setenv("UNIFI_HTTP_TIMEOUT", "2m")
	t.Setenv("UNIFI_SKIP_TLS_VERIFY", "true")
	got, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if got.UniFi.URL != "http://127.0.0.1:8443" || got.UniFi.HTTPTimeout != 2*time.Minute || !got.UniFi.SkipTLSVerify {
		t.Errorf("UniFi settings = (%q, %s, %t), want configured URL, 2m, true", got.UniFi.URL, got.UniFi.HTTPTimeout, got.UniFi.SkipTLSVerify)
	}

	for _, timeout := range []string{"0s", "-1s", "not-a-duration"} {
		t.Run("timeout/"+timeout, func(t *testing.T) {
			setValidConfigEnvironment(t)
			t.Setenv("UNIFI_HTTP_TIMEOUT", timeout)
			if _, err := LoadConfig(nil); err == nil {
				t.Fatalf("LoadConfig() accepted timeout %q", timeout)
			}
		})
	}

	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_SKIP_TLS_VERIFY", "sometimes")
	if _, err := LoadConfig(nil); err == nil {
		t.Fatal("LoadConfig() accepted a non-boolean TLS setting")
	}
}

func TestLoadConfigHelpDoesNotRequireCredentialsOrFiles(t *testing.T) {
	for _, name := range []string{
		"UNIFI_URL", "UNIFI_USERNAME", "UNIFI_USERNAME_FILE", "UNIFI_PASSWORD", "UNIFI_PASSWORD_FILE",
		"LEGO_HOOK_CERT_PATH", "LEGO_HOOK_CERT_KEY_PATH", "UNIFI_CLEANUP",
	} {
		t.Setenv(name, "")
	}
	_, err := LoadConfig([]string{"--help"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("LoadConfig(--help) error = %v, want flag.ErrHelp", err)
	}
}

func TestLoadConfigRejectsUnexpectedPositionalArguments(t *testing.T) {
	setValidConfigEnvironment(t)
	if _, err := LoadConfig([]string{"unexpected"}); err == nil {
		t.Fatal("LoadConfig() accepted a positional argument")
	}
}
