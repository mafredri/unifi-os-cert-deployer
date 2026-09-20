package main

import (
	"context"
	"crypto/sha1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func runCLI(ctx context.Context, args []string) (err error) {
	logger := slog.Default()
	cfg, err := LoadConfig(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return logRunFailure(logger, "configure", fmt.Errorf("load configuration: %w", err))
	}

	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return logRunFailure(logger, "read_certificate", fmt.Errorf("read certificate %q: %w", cfg.CertFile, err))
	}
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return logRunFailure(logger, "read_private_key", fmt.Errorf("read private key %q: %w", cfg.KeyFile, err))
	}
	certificate, _ := pem.Decode(certPEM)
	if certificate == nil || certificate.Type != "CERTIFICATE" {
		return logRunFailure(logger, "fingerprint", fmt.Errorf("decode certificate %q: expected a PEM CERTIFICATE block", cfg.CertFile))
	}
	// SHA-1 matches UniFi's displayed certificate fingerprint.
	fingerprint := sha1.Sum(certificate.Bytes)

	var errs []error
	for _, target := range cfg.Targets {
		if err := ctx.Err(); err != nil {
			logger.Error("Certificate operation canceled", "operation", "deploy", "error", err)
			return errors.Join(append(errs, err)...)
		}
		if err := deployTarget(ctx, target, certPEM, keyPEM, fingerprint); err != nil {
			name := target.ID
			if name == "" {
				name = "default"
			}
			errs = append(errs, fmt.Errorf("target %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func logRunFailure(logger *slog.Logger, operation string, err error) error {
	logger.Error("Certificate operation failed", "operation", operation, "error", err)
	return err
}

func deployTarget(ctx context.Context, target TargetConfig, certPEM, keyPEM []byte, fingerprint [sha1.Size]byte) (err error) {
	operation := "create_client"
	logger := slog.Default()
	if target.ID != "" {
		logger = logger.With("target_id", target.ID)
	}
	defer func() {
		if err != nil {
			logger.Error("Certificate operation failed", "operation", operation, "error", err)
		}
	}()
	client, err := NewUniFiClient(target.UniFi)
	if err != nil {
		return fmt.Errorf("create UniFi client: %w", err)
	}
	defer client.http.CloseIdleConnections()
	name := fmt.Sprintf("%s %x", target.Name, fingerprint[:4])
	logger = logger.With("target", client.baseURL, "certificate", name)
	operation = "login"
	logger.Debug("Logging in to UniFi", "operation", operation)
	if err := client.Login(ctx); err != nil {
		return err
	}
	logger.Debug("Logged in to UniFi", "operation", operation, "csrf_token_available", client.csrfToken != "")
	operation = "list"
	logger.Debug("Checking existing certificates", "operation", operation)
	certificates, err := client.ListCertificates(ctx)
	if err != nil {
		return err
	}
	apiFingerprint := strings.ReplaceAll(fmt.Sprintf("% X", fingerprint), " ", ":")
	existing, found, err := matchingCertificate(certificates, name, apiFingerprint)
	if err != nil {
		return err
	}
	var id string
	activate := false
	if found {
		if existing.ID == "" {
			return fmt.Errorf("existing certificate %q omitted id", name)
		}
		id = existing.ID
		logger = logger.With("certificate_id", id)
		if existing.Active == nil || !*existing.Active {
			activate = true
		} else {
			logger.Debug("Existing certificate is already active", "operation", operation)
		}
	} else {
		operation = "upload"
		logger.Debug("Uploading certificate", "operation", operation)
		id, err = client.UploadCertificate(ctx, name, certPEM, keyPEM)
		if err != nil {
			return err
		}
		logger = logger.With("certificate_id", id)
		logger.Debug("Certificate uploaded", "operation", operation)
		activate = true
	}
	if activate {
		operation = "activate"
		logger.Debug("Activating certificate", "operation", operation)
		if err := client.ActivateCertificate(ctx, id); err != nil {
			return err
		}
		logger.Info("Certificate activated", "operation", operation)
	}
	operation = "cleanup"
	if target.Cleanup {
		if err := cleanupExpiredCertificates(ctx, client, target.ID, target.Name); err != nil {
			return err
		}
	}
	return nil
}

func matchingCertificate(certificates []UniFiCertificate, name, fingerprint string) (UniFiCertificate, bool, error) {
	var match UniFiCertificate
	for _, certificate := range certificates {
		if certificate.Name != name {
			continue
		}
		if !strings.EqualFold(certificate.Fingerprint, fingerprint) {
			return UniFiCertificate{}, false, fmt.Errorf("certificate name collision for %q: fingerprint is missing, malformed, or different", name)
		}
		if match.ID != "" || match.Name != "" {
			return UniFiCertificate{}, false, fmt.Errorf("certificate name collision for %q: multiple matching certificates", name)
		}
		match = certificate
	}
	if match.Name == "" {
		return UniFiCertificate{}, false, nil
	}
	return match, true, nil
}

func cleanupExpiredCertificates(ctx context.Context, client *UniFiClient, targetID, baseName string) error {
	logger := slog.Default().With("target", client.baseURL, "operation", "cleanup")
	if targetID != "" {
		logger = logger.With("target_id", targetID)
	}
	logger.Debug("Checking expired certificates", "name", baseName)
	certificates, err := client.ListCertificates(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	deleted := 0
	for _, certificate := range certificates {
		if certificate.ID == "" || certificate.Active == nil || *certificate.Active {
			continue
		}
		nameStart := baseName + " "
		if !strings.HasPrefix(certificate.Name, nameStart) {
			continue
		}
		if len(certificate.Name) == len(nameStart) {
			continue
		}
		validTo, err := time.Parse(time.RFC3339Nano, certificate.ValidTo)
		if err != nil {
			continue
		}
		if !validTo.Before(now) {
			continue
		}
		logger.Debug("Deleting expired certificate", "certificate_id", certificate.ID)
		if err := client.DeleteCertificate(ctx, certificate.ID); err != nil {
			return err
		}
		deleted++
		logger.Debug("Expired certificate deleted", "certificate_id", certificate.ID)
	}
	if deleted > 0 {
		logger.Info("Certificate cleanup completed", "checked", len(certificates), "deleted", deleted)
	} else {
		logger.Debug("Certificate cleanup completed", "checked", len(certificates), "deleted", deleted)
	}
	return nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := runCLI(ctx, os.Args[1:])
	stop()
	if err != nil {
		os.Exit(1)
	}
}
