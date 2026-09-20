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
		"UNIFI_TARGETS":           "",
		"LEGO_HOOK_CERT_DOMAINS":  "",
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
	target := onlyConfiguredTarget(t, got)
	if target.Name != "unifi-os-le-cert-deployer" || target.Cleanup {
		t.Errorf("name/cleanup = (%q, %t), want default name and disabled cleanup", target.Name, target.Cleanup)
	}
	if target.UniFi.URL != "http://console.local" || target.UniFi.Username != "admin" || target.UniFi.Password != "console-password" {
		t.Errorf("UniFi settings not loaded correctly: URL=%q username=%q", target.UniFi.URL, target.UniFi.Username)
	}
	if target.UniFi.HTTPTimeout != 30*time.Second || target.UniFi.SkipTLSVerify {
		t.Errorf("UniFi HTTP settings = (%s, %t), want (30s, false)", target.UniFi.HTTPTimeout, target.UniFi.SkipTLSVerify)
	}
}

func TestLoadConfigFlagsOverrideHookEnvironment(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("LEGO_HOOK_CERT_PATH", "/hook/certificate.crt")
	t.Setenv("LEGO_HOOK_CERT_KEY_PATH", "/hook/key.pem")
	t.Setenv("UNIFI_CERT_FILE", "/own/fullchain.pem")
	t.Setenv("UNIFI_KEY_FILE", "/own/key.pem")
	t.Setenv("UNIFI_CERT_NAME", "environment-name")
	t.Setenv("UNIFI_CLEANUP", "true")

	got, err := LoadConfig([]string{
		"--cert", "/cli/fullchain.pem",
		"--key=/cli/key.pem",
		"--name", "cli-name: $host 100%",
		"--cleanup=false",
	})
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if got.CertFile != "/cli/fullchain.pem" || got.KeyFile != "/cli/key.pem" {
		t.Errorf("certificate paths = (%q, %q), want CLI paths", got.CertFile, got.KeyFile)
	}
	target := onlyConfiguredTarget(t, got)
	if target.Name != "cli-name: $host 100%" || target.Cleanup {
		t.Errorf("name/cleanup = (%q, %t), want literal CLI name and cleanup override", target.Name, target.Cleanup)
	}
}

func TestLoadConfigPrefersUniFiFilesOverLegoPaths(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_CERT_FILE", "/own/fullchain.pem")
	t.Setenv("UNIFI_KEY_FILE", "/own/key.pem")
	t.Setenv("RENEWED_LINEAGE", "/certbot/live/console")

	got, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if got.CertFile != "/own/fullchain.pem" || got.KeyFile != "/own/key.pem" {
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
	wantCert := filepath.Join("/etc/letsencrypt", "live", "console", "fullchain.pem")
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
				t.Setenv("UNIFI_CERT_FILE", "/own/fullchain.pem")
				t.Setenv("UNIFI_KEY_FILE", "")
			},
			args: []string{"--key", "/cli/key.pem"}, cert: "/own/fullchain.pem", key: "/cli/key.pem",
		},
		{
			name: "partial UniFi pair does not borrow lego key",
			setup: func(t *testing.T) {
				t.Setenv("UNIFI_CERT_FILE", "/own/fullchain.pem")
				t.Setenv("UNIFI_KEY_FILE", "")
			},
			wantErr: true,
		},
		{
			name: "partial lego pair blocks Certbot fallback",
			setup: func(t *testing.T) {
				t.Setenv("UNIFI_CERT_FILE", "")
				t.Setenv("UNIFI_KEY_FILE", "")
				t.Setenv("LEGO_HOOK_CERT_PATH", "/lego/certificate.crt")
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
	if !onlyConfiguredTarget(t, got).Cleanup {
		t.Fatal("LoadConfig() ignored UNIFI_CLEANUP=true")
	}

	setValidConfigEnvironment(t)
	got, err = LoadConfig([]string{"--cleanup"})
	if err != nil {
		t.Fatalf("LoadConfig(--cleanup) error = %v", err)
	}
	if !onlyConfiguredTarget(t, got).Cleanup {
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
	target := onlyConfiguredTarget(t, got)
	if target.UniFi.Username != "file-admin" || target.UniFi.Password != "file-password " {
		t.Errorf("UniFi credentials = (%q, %q), want file contents with only line endings removed", target.UniFi.Username, target.UniFi.Password)
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
	target := onlyConfiguredTarget(t, got)
	if target.UniFi.URL != "http://127.0.0.1:8443" || target.UniFi.HTTPTimeout != 2*time.Minute || !target.UniFi.SkipTLSVerify {
		t.Errorf("UniFi settings = (%q, %s, %t), want configured URL, 2m, true", target.UniFi.URL, target.UniFi.HTTPTimeout, target.UniFi.SkipTLSVerify)
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

func TestLoadConfigSelectsConfiguredTargetsByLiteralHookDomain(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_TARGETS", " HOME , , Protect ")
	t.Setenv("LEGO_HOOK_CERT_DOMAINS", "home.example, *")
	t.Setenv("UNIFI_CERT_NAME", "global-name-must-not-apply")
	setConfiguredTarget(t, configuredTargetEnvironment{
		ID:       "HOME",
		Domain:   "home.example",
		URL:      "http://home.local",
		Username: "home-user",
		Password: "home-password",
	})
	setConfiguredTarget(t, configuredTargetEnvironment{
		ID:       "PROTECT",
		Domain:   "*",
		URL:      "http://protect.local",
		Username: "protect-user",
		Password: "protect-password",
	})
	t.Setenv("UNIFI_HOME_CERT_NAME", "home-name")
	t.Setenv("UNIFI_HOME_CLEANUP", "true")
	t.Setenv("UNIFI_PROTECT_CERT_NAME", "protect-name")

	got, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if len(got.Targets) != 2 {
		t.Fatalf("configured targets = %d, want two", len(got.Targets))
	}
	home, protect := got.Targets[0], got.Targets[1]
	if home.ID != "home" {
		t.Errorf("home ID = %q, want home", home.ID)
	}
	if home.UniFi.URL != "http://home.local" {
		t.Errorf("home URL = %q, want configured URL", home.UniFi.URL)
	}
	if home.UniFi.Username != "home-user" {
		t.Error("home target did not load its username")
	}
	if home.Name != "home-name" || !home.Cleanup {
		t.Errorf("home name/cleanup = (%q, %t), want (home-name, true)", home.Name, home.Cleanup)
	}
	if protect.ID != "protect" {
		t.Errorf("protect ID = %q, want protect", protect.ID)
	}
	if protect.UniFi.URL != "http://protect.local" {
		t.Errorf("protect URL = %q, want configured URL", protect.UniFi.URL)
	}
	if protect.UniFi.Username != "protect-user" {
		t.Error("protect target did not load its username")
	}
	if protect.Name != "protect-name" || protect.Cleanup {
		t.Errorf("protect name/cleanup = (%q, %t), want (protect-name, false)", protect.Name, protect.Cleanup)
	}
}

func TestLoadConfigRejectsInvalidOrDuplicateTargetIDs(t *testing.T) {
	for _, value := range []string{"home,HOME", "home,protect!", "home,home"} {
		t.Run(value, func(t *testing.T) {
			setValidConfigEnvironment(t)
			t.Setenv("UNIFI_TARGETS", value)
			if _, err := LoadConfig(nil); err == nil {
				t.Fatalf("LoadConfig() accepted UNIFI_TARGETS=%q", value)
			}
		})
	}
}

func TestLoadConfigExplicitTargetBypassesHookDomainsAndLoadsOnlyIt(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_TARGETS", "home,,protect")
	t.Setenv("LEGO_HOOK_CERT_DOMAINS", "")
	setConfiguredTarget(t, configuredTargetEnvironment{
		ID:       "HOME",
		Domain:   "home.example",
		URL:      "http://home.local",
		Username: "home-user",
		Password: "home-password",
	})
	t.Setenv("UNIFI_PROTECT_USERNAME", "")
	t.Setenv("UNIFI_PROTECT_PASSWORD", "")
	got, err := LoadConfig([]string{"--target", "HOME"})
	if err != nil {
		t.Fatalf("LoadConfig(--target home) error = %v", err)
	}
	target := onlyConfiguredTarget(t, got)
	if target.ID != "home" {
		t.Errorf("explicit target ID = %q, want home", target.ID)
	}
	if target.UniFi.Username != "home-user" {
		t.Error("explicit target did not load home credentials")
	}
	if _, err := LoadConfig([]string{"--target", "missing"}); err == nil {
		t.Fatal("LoadConfig() accepted an unknown target")
	}
}

func TestLoadConfigUsesSingleTargetForOnlyEmptyTargetEntries(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_TARGETS", " , , ")
	got, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("LoadConfig() with empty target entries error = %v", err)
	}
	target := onlyConfiguredTarget(t, got)
	if target.ID != "" {
		t.Errorf("target ID = %q, want the single-target ID", target.ID)
	}
	if target.UniFi.URL != "http://console.local" {
		t.Error("empty target entries did not use single-target settings")
	}
}

func TestLoadConfigRejectsTargetFlagWithoutTargetMode(t *testing.T) {
	setValidConfigEnvironment(t)
	if _, err := LoadConfig([]string{"--target", "home"}); err == nil {
		t.Fatal("LoadConfig() accepted --target without UNIFI_TARGETS")
	}
}

func TestLoadConfigRejectsUnmatchedTargetDomains(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_TARGETS", "home")
	t.Setenv("LEGO_HOOK_CERT_DOMAINS", "other.example")
	setConfiguredTarget(t, configuredTargetEnvironment{
		ID:       "HOME",
		Domain:   "home.example",
		URL:      "http://home.local",
		Username: "home-user",
		Password: "home-password",
	})
	if _, err := LoadConfig(nil); err == nil {
		t.Fatal("LoadConfig() accepted hook domains without a configured match")
	}
}

func TestLoadConfigFlagsOverrideSelectedTargetSettings(t *testing.T) {
	setValidConfigEnvironment(t)
	t.Setenv("UNIFI_TARGETS", "home")
	t.Setenv("LEGO_HOOK_CERT_DOMAINS", "other.example")
	setConfiguredTarget(t, configuredTargetEnvironment{
		ID:       "HOME",
		Domain:   "home.example",
		URL:      "http://home.local",
		Username: "home-user",
		Password: "home-password",
	})
	got, err := LoadConfig([]string{"--target=home", "--name", "cli-name", "--cleanup=false"})
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	target := onlyConfiguredTarget(t, got)
	if target.Name != "cli-name" || target.Cleanup {
		t.Errorf("target overrides = (%q, %t), want (cli-name, false)", target.Name, target.Cleanup)
	}
}

type configuredTargetEnvironment struct {
	ID       string
	Domain   string
	URL      string
	Username string
	Password string
}

func setConfiguredTarget(t *testing.T, target configuredTargetEnvironment) {
	t.Helper()
	envBase := "UNIFI_" + target.ID
	for name, value := range map[string]string{
		envBase + "_DOMAIN":          target.Domain,
		envBase + "_URL":             target.URL,
		envBase + "_USERNAME":        target.Username,
		envBase + "_USERNAME_FILE":   "",
		envBase + "_PASSWORD":        target.Password,
		envBase + "_PASSWORD_FILE":   "",
		envBase + "_HTTP_TIMEOUT":    "",
		envBase + "_SKIP_TLS_VERIFY": "",
		envBase + "_CERT_NAME":       "",
		envBase + "_CLEANUP":         "",
	} {
		t.Setenv(name, value)
	}
}

func onlyConfiguredTarget(t *testing.T, cfg Config) TargetConfig {
	t.Helper()
	if len(cfg.Targets) != 1 {
		t.Fatalf("configured targets = %d, want one", len(cfg.Targets))
	}
	return cfg.Targets[0]
}
