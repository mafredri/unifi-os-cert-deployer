package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultUniFiHTTPTimeout = 30 * time.Second
	defaultCertificateName  = "unifi-os-le-cert-deployer"
)

type Config struct {
	UniFi    UniFiConfig
	CertFile string
	KeyFile  string
	Name     string
	Cleanup  bool
}

func LoadConfig(args []string) (Config, error) {
	var cfg Config

	certPath := os.Getenv("UNIFI_CERT_FILE")
	keyPath := os.Getenv("UNIFI_KEY_FILE")
	if certPath == "" && keyPath == "" {
		certPath = os.Getenv("LEGO_HOOK_CERT_PATH")
		keyPath = os.Getenv("LEGO_HOOK_CERT_KEY_PATH")
	}
	if certPath == "" && keyPath == "" {
		if lineage := os.Getenv("RENEWED_LINEAGE"); lineage != "" {
			certPath = filepath.Join(lineage, "cert.pem")
			keyPath = filepath.Join(lineage, "privkey.pem")
		}
	}

	flags := flag.NewFlagSet("unifi-cert-upload", flag.ContinueOnError)
	certFile := flags.String("cert", certPath, "path to the certificate PEM")
	keyFile := flags.String("key", keyPath, "path to the private key PEM")
	name := flags.String("name", envOrDefault("UNIFI_CERT_NAME", defaultCertificateName), "certificate name; a space and the first 8 hex digits of its SHA-1 fingerprint are appended")
	cleanup := flags.Bool("cleanup", false, "delete expired inactive certificates with this configured name")
	if err := flags.Parse(args); err != nil {
		return cfg, err
	}
	if flags.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
	}
	var err error

	cfg.CertFile = *certFile
	cfg.KeyFile = *keyFile
	cfg.Name = *name
	cfg.Cleanup, err = boolValue("UNIFI_CLEANUP", false)
	if err != nil {
		return cfg, err
	}
	flags.Visit(func(parsed *flag.Flag) {
		if parsed.Name == "cleanup" {
			cfg.Cleanup = *cleanup
		}
	})
	if cfg.CertFile == "" {
		return cfg, fmt.Errorf("--cert, UNIFI_CERT_FILE, LEGO_HOOK_CERT_PATH, or RENEWED_LINEAGE is required")
	}
	if cfg.KeyFile == "" {
		return cfg, fmt.Errorf("--key, UNIFI_KEY_FILE, LEGO_HOOK_CERT_KEY_PATH, or RENEWED_LINEAGE is required")
	}

	cfg.UniFi.URL = os.Getenv("UNIFI_URL")
	if strings.TrimSpace(cfg.UniFi.URL) == "" {
		return cfg, fmt.Errorf("UNIFI_URL is required")
	}
	cfg.UniFi.Username, err = secretValue("UNIFI_USERNAME", "UNIFI_USERNAME_FILE")
	if err != nil {
		return cfg, err
	}
	if strings.TrimSpace(cfg.UniFi.Username) == "" {
		return cfg, fmt.Errorf("UNIFI_USERNAME or UNIFI_USERNAME_FILE is required")
	}
	cfg.UniFi.Password, err = secretValue("UNIFI_PASSWORD", "UNIFI_PASSWORD_FILE")
	if err != nil {
		return cfg, err
	}
	if strings.TrimSpace(cfg.UniFi.Password) == "" {
		return cfg, fmt.Errorf("UNIFI_PASSWORD or UNIFI_PASSWORD_FILE is required")
	}
	cfg.UniFi.HTTPTimeout, err = durationValue("UNIFI_HTTP_TIMEOUT", defaultUniFiHTTPTimeout)
	if err != nil {
		return cfg, err
	}
	cfg.UniFi.SkipTLSVerify, err = boolValue("UNIFI_SKIP_TLS_VERIFY", false)
	if err != nil {
		return cfg, err
	}

	return cfg, nil
}

func secretValue(valueName, fileName string) (string, error) {
	value := os.Getenv(valueName)
	file := os.Getenv(fileName)
	if value != "" && file != "" {
		return "", fmt.Errorf("set only one of %s and %s", valueName, fileName)
	}
	if value != "" {
		return value, nil
	}
	if file == "" {
		return "", nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileName, err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

func durationValue(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return duration, nil
}

func boolValue(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
