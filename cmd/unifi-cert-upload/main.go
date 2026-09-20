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
	operation := "configure"
	defer func() {
		if err != nil {
			logger.Error("Certificate operation failed", "operation", operation, "error", err)
		}
	}()

	cfg, err := LoadConfig(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	operation = "read_certificate"
	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return fmt.Errorf("read certificate %q: %w", cfg.CertFile, err)
	}
	operation = "read_private_key"
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("read private key %q: %w", cfg.KeyFile, err)
	}
	operation = "fingerprint"
	certificate, _ := pem.Decode(certPEM)
	if certificate == nil || certificate.Type != "CERTIFICATE" {
		return fmt.Errorf("decode certificate %q: expected a PEM CERTIFICATE block", cfg.CertFile)
	}
	// SHA-1 matches UniFi's displayed certificate fingerprint.
	fingerprint := sha1.Sum(certificate.Bytes)

	operation = "create_client"
	client, err := NewUniFiClient(cfg.UniFi)
	if err != nil {
		return fmt.Errorf("create UniFi client: %w", err)
	}
	name := fmt.Sprintf("%s %x", cfg.Name, fingerprint[:4])
	logger = logger.With("target", client.baseURL, "certificate", name)
	operation = "login"
	logger.Info("Logging in to UniFi", "operation", operation)
	if err := client.Login(ctx); err != nil {
		return err
	}
	logger.Info("Logged in to UniFi", "operation", operation, "csrf_token_available", client.csrfToken != "")
	operation = "upload"
	logger.Info("Uploading certificate", "operation", operation)
	id, err := client.UploadCertificate(ctx, name, certPEM, keyPEM)
	if err != nil {
		return err
	}
	logger = logger.With("certificate_id", id)
	logger.Info("Certificate uploaded", "operation", operation)
	operation = "activate"
	logger.Info("Activating certificate", "operation", operation)
	if err := client.ActivateCertificate(ctx, id); err != nil {
		return err
	}
	logger.Info("Certificate activated", "operation", operation)
	operation = "cleanup"
	if cfg.Cleanup {
		if err := cleanupExpiredCertificates(ctx, client, cfg.Name); err != nil {
			return err
		}
	}
	return nil
}

func cleanupExpiredCertificates(ctx context.Context, client *UniFiClient, baseName string) error {
	logger := slog.Default().With("target", client.baseURL, "operation", "cleanup")
	logger.Info("Checking expired certificates", "name", baseName)
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
		logger.Info("Deleting expired certificate", "certificate_id", certificate.ID)
		if err := client.DeleteCertificate(ctx, certificate.ID); err != nil {
			return err
		}
		deleted++
		logger.Info("Expired certificate deleted", "certificate_id", certificate.ID)
	}
	logger.Info("Certificate cleanup completed", "checked", len(certificates), "deleted", deleted)
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
