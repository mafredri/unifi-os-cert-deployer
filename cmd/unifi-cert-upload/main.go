package main

import (
	"context"
	"crypto/sha1"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func runCLI(ctx context.Context, args []string) error {
	cfg, err := LoadConfig(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return fmt.Errorf("read certificate %q: %w", cfg.CertFile, err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("read private key %q: %w", cfg.KeyFile, err)
	}
	certificate, _ := pem.Decode(certPEM)
	if certificate == nil || certificate.Type != "CERTIFICATE" {
		return fmt.Errorf("decode certificate %q: expected a PEM CERTIFICATE block", cfg.CertFile)
	}
	// SHA-1 matches UniFi's displayed certificate fingerprint.
	fingerprint := sha1.Sum(certificate.Bytes)

	client, err := NewUniFiClient(cfg.UniFi)
	if err != nil {
		return fmt.Errorf("create UniFi client: %w", err)
	}
	name := fmt.Sprintf("%s %x", cfg.Name, fingerprint[:4])
	if err := client.Login(ctx); err != nil {
		return fmt.Errorf("log in to UniFi: %w", err)
	}
	id, err := client.UploadCertificate(ctx, name, certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("upload certificate: %w", err)
	}
	if err := client.ActivateCertificate(ctx, id); err != nil {
		return fmt.Errorf("activate certificate: %w", err)
	}
	if cfg.Cleanup {
		if err := cleanupExpiredCertificates(ctx, client, cfg.Name); err != nil {
			return fmt.Errorf("clean up expired certificates: %w", err)
		}
	}
	return nil
}

func cleanupExpiredCertificates(ctx context.Context, client *UniFiClient, baseName string) error {
	certificates, err := client.ListCertificates(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
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
		if err := client.DeleteCertificate(ctx, certificate.ID); err != nil {
			return fmt.Errorf("delete expired UniFi certificate: %w", err)
		}
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := runCLI(ctx, os.Args[1:])
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
