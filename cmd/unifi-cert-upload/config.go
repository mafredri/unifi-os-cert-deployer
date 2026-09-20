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
	CertFile string
	KeyFile  string
	Targets  []TargetConfig
}

type TargetConfig struct {
	ID      string
	UniFi   UniFiConfig
	Name    string
	Cleanup bool
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
	name := flags.String("name", "", "certificate name; a space and the first 8 hex digits of its SHA-1 fingerprint are appended")
	cleanup := flags.Bool("cleanup", false, "delete expired inactive certificates with this configured name")
	target := flags.String("target", "", "configured UniFi target to deploy")
	if err := flags.Parse(args); err != nil {
		return cfg, err
	}
	if flags.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
	}
	cfg.CertFile = *certFile
	cfg.KeyFile = *keyFile
	nameSet := false
	cleanupSet := false
	targetSet := false
	flags.Visit(func(parsed *flag.Flag) {
		switch parsed.Name {
		case "name":
			nameSet = true
		case "cleanup":
			cleanupSet = true
		case "target":
			targetSet = true
		}
	})
	if cfg.CertFile == "" {
		return cfg, fmt.Errorf("--cert, UNIFI_CERT_FILE, LEGO_HOOK_CERT_PATH, or RENEWED_LINEAGE is required")
	}
	if cfg.KeyFile == "" {
		return cfg, fmt.Errorf("--key, UNIFI_KEY_FILE, LEGO_HOOK_CERT_KEY_PATH, or RENEWED_LINEAGE is required")
	}

	ids, err := targetIDs(os.Getenv("UNIFI_TARGETS"))
	if err != nil {
		return cfg, err
	}
	if len(ids) == 0 {
		if targetSet {
			return cfg, fmt.Errorf("--target requires UNIFI_TARGETS")
		}
		selected, err := loadTarget("", "UNIFI", nameSet, *name, cleanupSet, *cleanup)
		if err != nil {
			return cfg, err
		}
		cfg.Targets = []TargetConfig{selected}
		return cfg, nil
	}

	var selectedIDs []string
	if targetSet {
		selectedIDs, err = selectTargetID(ids, strings.TrimSpace(*target))
		if err != nil {
			return cfg, err
		}
	} else {
		selectedIDs, err = targetsForHookDomains(ids)
		if err != nil {
			return cfg, err
		}
	}
	for _, id := range selectedIDs {
		envBase := "UNIFI_" + strings.ToUpper(id)
		selected, err := loadTarget(id, envBase, nameSet, *name, cleanupSet, *cleanup)
		if err != nil {
			return cfg, err
		}
		cfg.Targets = append(cfg.Targets, selected)
	}
	return cfg, nil
}

func targetIDs(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	seen := make(map[string]bool)
	var ids []string
	for _, rawID := range strings.Split(value, ",") {
		id := strings.ToLower(strings.TrimSpace(rawID))
		if id == "" {
			continue
		}
		if !validTargetID(id) {
			return nil, fmt.Errorf("UNIFI_TARGETS contains invalid target %q", rawID)
		}
		if seen[id] {
			return nil, fmt.Errorf("UNIFI_TARGETS contains duplicate target %q", id)
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

func validTargetID(id string) bool {
	if id == "" {
		return false
	}
	for _, character := range id {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func selectTargetID(ids []string, target string) ([]string, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, id := range ids {
		if id == target {
			return []string{id}, nil
		}
	}
	return nil, fmt.Errorf("unknown UniFi target %q", target)
}

func targetsForHookDomains(ids []string) ([]string, error) {
	hookDomains := make(map[string]bool)
	for _, value := range strings.Split(os.Getenv("LEGO_HOOK_CERT_DOMAINS"), ",") {
		if domain := strings.TrimSpace(value); domain != "" {
			hookDomains[domain] = true
		}
	}
	if len(hookDomains) == 0 {
		return nil, fmt.Errorf("LEGO_HOOK_CERT_DOMAINS is required with UNIFI_TARGETS unless --target is set")
	}
	var selected []string
	for _, id := range ids {
		domain := strings.TrimSpace(os.Getenv("UNIFI_" + strings.ToUpper(id) + "_DOMAIN"))
		if domain == "" {
			return nil, fmt.Errorf("UNIFI_%s_DOMAIN is required", strings.ToUpper(id))
		}
		if hookDomains[domain] {
			selected = append(selected, id)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no configured UniFi target matches LEGO_HOOK_CERT_DOMAINS")
	}
	return selected, nil
}

func loadTarget(id, envBase string, nameSet bool, name string, cleanupSet bool, cleanup bool) (TargetConfig, error) {
	target := TargetConfig{ID: id}
	target.UniFi.URL = os.Getenv(envBase + "_URL")
	if strings.TrimSpace(target.UniFi.URL) == "" {
		return target, fmt.Errorf("%s_URL is required", envBase)
	}
	var err error
	target.UniFi.Username, err = secretValue(envBase+"_USERNAME", envBase+"_USERNAME_FILE")
	if err != nil {
		return target, err
	}
	if strings.TrimSpace(target.UniFi.Username) == "" {
		return target, fmt.Errorf("%s_USERNAME or %s_USERNAME_FILE is required", envBase, envBase)
	}
	target.UniFi.Password, err = secretValue(envBase+"_PASSWORD", envBase+"_PASSWORD_FILE")
	if err != nil {
		return target, err
	}
	if strings.TrimSpace(target.UniFi.Password) == "" {
		return target, fmt.Errorf("%s_PASSWORD or %s_PASSWORD_FILE is required", envBase, envBase)
	}
	target.UniFi.HTTPTimeout, err = durationValue(envBase+"_HTTP_TIMEOUT", defaultUniFiHTTPTimeout)
	if err != nil {
		return target, err
	}
	target.UniFi.SkipTLSVerify, err = boolValue(envBase+"_SKIP_TLS_VERIFY", false)
	if err != nil {
		return target, err
	}
	target.Name = envOrDefault(envBase+"_CERT_NAME", defaultCertificateName)
	if nameSet {
		target.Name = name
	}
	target.Cleanup, err = boolValue(envBase+"_CLEANUP", false)
	if err != nil {
		return target, err
	}
	if cleanupSet {
		target.Cleanup = cleanup
	}
	return target, nil
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
