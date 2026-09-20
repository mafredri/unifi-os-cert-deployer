package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	if api.certificateLists != 1 {
		t.Errorf("certificate lists = %d, want one before upload", api.certificateLists)
	}
}

func TestRunCLIDeploysMatchingTargetsWithIndependentSettings(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	keyPEM := []byte("same certificate key bytes")
	home := &uploadAPIFixture{
		wantCert: string(certPEM),
		wantKey:  string(keyPEM),
		username: "home-user",
		password: "home-password",
	}
	protect := &uploadAPIFixture{
		wantCert: string(certPEM),
		wantKey:  string(keyPEM),
		username: "protect-user",
		password: "protect-password",
	}
	homeServer := httptest.NewServer(home)
	defer homeServer.Close()
	protectServer := httptest.NewServer(protect)
	defer protectServer.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, keyPEM)
	setUploadEnvironment(t, "http://global-settings-must-not-apply", certFile, keyFile)
	t.Setenv("UNIFI_TARGETS", "home,protect")
	t.Setenv("LEGO_HOOK_CERT_DOMAINS", "home.example, protect.example")
	setTargetUploadEnvironment(t, targetUploadEnvironment{
		ID:              "HOME",
		Domain:          "home.example",
		URL:             homeServer.URL,
		Username:        "home-user",
		Password:        "home-password",
		CertificateName: "home cert",
		Cleanup:         "true",
	})
	setTargetUploadEnvironment(t, targetUploadEnvironment{
		ID:              "PROTECT",
		Domain:          "protect.example",
		URL:             protectServer.URL,
		Username:        "protect-user",
		Password:        "protect-password",
		CertificateName: "protect cert",
		Cleanup:         "false",
	})

	if err := runCLI(t.Context(), nil); err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}
	if home.logins != 1 || home.uploads != 1 || home.activations != 1 {
		t.Errorf("home API calls = login:%d upload:%d activate:%d, want one each", home.logins, home.uploads, home.activations)
	}
	if protect.logins != 1 || protect.uploads != 1 || protect.activations != 1 {
		t.Errorf("protect API calls = login:%d upload:%d activate:%d, want one each", protect.logins, protect.uploads, protect.activations)
	}
	if home.name != "home cert cabd2a79" {
		t.Errorf("home uploaded name = %q, want independent configured name", home.name)
	}
	if protect.name != "protect cert cabd2a79" {
		t.Errorf("protect uploaded name = %q, want independent configured name", protect.name)
	}
	if home.certificateLists != 2 {
		t.Errorf("home certificate lists = %d, want ownership and cleanup checks", home.certificateLists)
	}
	if protect.certificateLists != 1 {
		t.Errorf("protect certificate lists = %d, want one before upload", protect.certificateLists)
	}
}

func TestRunCLIMultiTargetMakesNoRequestsForUnmatchedDomains(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	api := &uploadAPIFixture{}
	server := httptest.NewServer(api)
	defer server.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("key"))
	setUploadEnvironment(t, server.URL, certFile, keyFile)
	t.Setenv("UNIFI_TARGETS", "home")
	t.Setenv("LEGO_HOOK_CERT_DOMAINS", "other.example")
	setTargetUploadEnvironment(t, targetUploadEnvironment{
		ID:              "HOME",
		Domain:          "home.example",
		URL:             server.URL,
		Username:        "home-user",
		Password:        "home-password",
		CertificateName: "home cert",
		Cleanup:         "false",
	})

	if err := runCLI(t.Context(), nil); err == nil {
		t.Fatal("runCLI() succeeded without a matching configured target")
	}
	if api.logins != 0 || api.uploads != 0 || api.activations != 0 || api.certificateLists != 0 {
		t.Errorf("API calls = login:%d upload:%d activate:%d list:%d, want none", api.logins, api.uploads, api.activations, api.certificateLists)
	}
}

func TestRunCLIMultiTargetContinuesAfterTargetFailure(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	keyPEM := []byte("key")
	home := &uploadAPIFixture{
		wantCert:        string(certPEM),
		wantKey:         string(keyPEM),
		username:        "home-user",
		password:        "home-password",
		rejectDuplicate: true,
		name:            "home cert cabd2a79",
	}
	protect := &uploadAPIFixture{
		wantCert: string(certPEM),
		wantKey:  string(keyPEM),
		username: "protect-user",
		password: "protect-password",
	}
	homeServer := httptest.NewServer(home)
	defer homeServer.Close()
	protectServer := httptest.NewServer(protect)
	defer protectServer.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, keyPEM)
	setUploadEnvironment(t, "http://global-settings-must-not-apply", certFile, keyFile)
	t.Setenv("UNIFI_TARGETS", "home,protect")
	t.Setenv("LEGO_HOOK_CERT_DOMAINS", "home.example,protect.example")
	setTargetUploadEnvironment(t, targetUploadEnvironment{
		ID:              "HOME",
		Domain:          "home.example",
		URL:             homeServer.URL,
		Username:        "home-user",
		Password:        "home-password",
		CertificateName: "home cert",
		Cleanup:         "false",
	})
	setTargetUploadEnvironment(t, targetUploadEnvironment{
		ID:              "PROTECT",
		Domain:          "protect.example",
		URL:             protectServer.URL,
		Username:        "protect-user",
		Password:        "protect-password",
		CertificateName: "protect cert",
		Cleanup:         "false",
	})

	err := runCLI(t.Context(), nil)
	if err == nil || !strings.Contains(err.Error(), "target home") {
		t.Fatalf("runCLI() error = %v, want target-scoped home failure", err)
	}
	if home.activations != 0 {
		t.Errorf("home activations = %d, want none after upload failure", home.activations)
	}
	if protect.activations != 1 {
		t.Errorf("protect activations = %d, want one after home failure", protect.activations)
	}
}

func TestRunCLIMultiTargetRetryDoesNotDuplicatePartialSuccesses(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	keyPEM := []byte("key")
	home := &uploadAPIFixture{
		wantCert:              string(certPEM),
		wantKey:               string(keyPEM),
		username:              "home-user",
		password:              "home-password",
		rejectActivationCount: 1,
	}
	protect := &uploadAPIFixture{
		wantCert: string(certPEM),
		wantKey:  string(keyPEM),
		username: "protect-user",
		password: "protect-password",
	}
	homeServer := httptest.NewServer(home)
	defer homeServer.Close()
	protectServer := httptest.NewServer(protect)
	defer protectServer.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, keyPEM)
	setUploadEnvironment(t, "http://global-settings-must-not-apply", certFile, keyFile)
	t.Setenv("UNIFI_TARGETS", "home,protect")
	t.Setenv("LEGO_HOOK_CERT_DOMAINS", "home.example,protect.example")
	setTargetUploadEnvironment(t, targetUploadEnvironment{
		ID:              "HOME",
		Domain:          "home.example",
		URL:             homeServer.URL,
		Username:        "home-user",
		Password:        "home-password",
		CertificateName: "home cert",
		Cleanup:         "false",
	})
	setTargetUploadEnvironment(t, targetUploadEnvironment{
		ID:              "PROTECT",
		Domain:          "protect.example",
		URL:             protectServer.URL,
		Username:        "protect-user",
		Password:        "protect-password",
		CertificateName: "protect cert",
		Cleanup:         "false",
	})

	if err := runCLI(t.Context(), nil); err == nil || !strings.Contains(err.Error(), "target home") {
		t.Fatalf("first runCLI() error = %v, want target-scoped activation failure", err)
	}
	if err := runCLI(t.Context(), nil); err != nil {
		t.Fatalf("second runCLI() error = %v", err)
	}
	if home.uploads != 1 || home.activations != 2 {
		t.Errorf("home calls = upload:%d activate:%d, want 1,2", home.uploads, home.activations)
	}
	if protect.uploads != 1 || protect.activations != 1 {
		t.Errorf("protect calls = upload:%d activate:%d, want 1,1", protect.uploads, protect.activations)
	}
}

func TestRunCLIMultiTargetStopsAfterCancellation(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	keyPEM := []byte("key")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	home := &uploadAPIFixture{
		wantCert:        string(certPEM),
		wantKey:         string(keyPEM),
		username:        "home-user",
		password:        "home-password",
		afterActivation: cancel,
	}
	protect := &uploadAPIFixture{
		wantCert: string(certPEM),
		wantKey:  string(keyPEM),
		username: "protect-user",
		password: "protect-password",
	}
	homeServer := httptest.NewServer(home)
	defer homeServer.Close()
	protectServer := httptest.NewServer(protect)
	defer protectServer.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, keyPEM)
	setUploadEnvironment(t, "http://global-settings-must-not-apply", certFile, keyFile)
	t.Setenv("UNIFI_TARGETS", "home,protect")
	t.Setenv("LEGO_HOOK_CERT_DOMAINS", "home.example,protect.example")
	setTargetUploadEnvironment(t, targetUploadEnvironment{
		ID:              "HOME",
		Domain:          "home.example",
		URL:             homeServer.URL,
		Username:        "home-user",
		Password:        "home-password",
		CertificateName: "home cert",
		Cleanup:         "false",
	})
	setTargetUploadEnvironment(t, targetUploadEnvironment{
		ID:              "PROTECT",
		Domain:          "protect.example",
		URL:             protectServer.URL,
		Username:        "protect-user",
		Password:        "protect-password",
		CertificateName: "protect cert",
		Cleanup:         "false",
	})

	err := runCLI(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runCLI() error = %v, want context cancellation", err)
	}
	if home.activations != 1 {
		t.Errorf("home activations = %d, want one before cancellation", home.activations)
	}
	if protect.logins != 0 {
		t.Errorf("protect logins = %d, want no deployment after cancellation", protect.logins)
	}
}

func TestRunCLILogsOperationsWithoutSecrets(t *testing.T) {
	for _, tt := range []struct {
		name           string
		logLevel       slog.Level
		cleanupDeletes bool
		rejectUpload   bool
		wantMessages   []string
		absentMessages []string
	}{
		{
			name:           "info deployment with cleanup",
			logLevel:       slog.LevelInfo,
			cleanupDeletes: true,
			wantMessages: []string{
				"Certificate activated",
				"Certificate cleanup completed",
				"deleted=1",
			},
			absentMessages: []string{
				"Logging in to UniFi",
				"Certificate uploaded",
				"Activating certificate",
				"Expired certificate deleted",
			},
		},
		{
			name:           "info cleanup without deletion",
			logLevel:       slog.LevelInfo,
			wantMessages:   []string{"Certificate activated"},
			absentMessages: []string{"Certificate cleanup completed"},
		},
		{
			name:           "debug deployment with cleanup",
			logLevel:       slog.LevelDebug,
			cleanupDeletes: true,
			wantMessages: []string{
				"Logging in to UniFi",
				"Logged in to UniFi",
				"csrf_token_available=true",
				"Checking existing certificates",
				"Uploading certificate",
				"Certificate uploaded",
				"Activating certificate",
				"Certificate activated",
				"Checking expired certificates",
				"Deleting expired certificate",
				"Expired certificate deleted",
				"Certificate cleanup completed",
				"deleted=1",
			},
		},
		{
			name:           "info upload rejected",
			logLevel:       slog.LevelInfo,
			cleanupDeletes: true,
			rejectUpload:   true,
			wantMessages: []string{
				"Certificate operation failed",
				"operation=upload",
				"409 Conflict",
			},
			absentMessages: []string{"Uploading certificate", "Certificate uploaded", "Activating certificate", "Checking expired certificates"},
		},
		{
			name:           "debug upload rejected",
			logLevel:       slog.LevelDebug,
			cleanupDeletes: true,
			rejectUpload:   true,
			wantMessages: []string{
				"Uploading certificate",
				"Certificate operation failed",
				"operation=upload",
				"409 Conflict",
			},
			absentMessages: []string{"Certificate uploaded", "Activating certificate", "Checking expired certificates"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			previousLogger := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: tt.logLevel})))
			t.Cleanup(func() { slog.SetDefault(previousLogger) })
			certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
			keyPEM := []byte("private-key-secret-marker")
			api := &uploadAPIFixture{
				wantCert:        string(certPEM),
				wantKey:         string(keyPEM),
				rejectDuplicate: tt.rejectUpload,
				name:            "fixture [prod] cabd2a79",
			}
			if tt.cleanupDeletes {
				api.cleanupName = "fixture [prod]"
			}
			server := httptest.NewServer(api)
			defer server.Close()
			certFile, keyFile := writeCLIInputFiles(t, certPEM, keyPEM)
			setUploadEnvironment(t, server.URL, certFile, keyFile)
			t.Setenv("UNIFI_CERT_NAME", "fixture [prod]")
			t.Setenv("UNIFI_CLEANUP", "true")

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
	if api.certificateLists != 2 {
		t.Fatalf("certificate lists = %d, want ownership and cleanup checks", api.certificateLists)
	}
	want := []string{"/api/userCertificates/expired%2Fmatch"}
	if fmt.Sprint(api.deletions) != fmt.Sprint(want) {
		t.Fatalf("deleted certificate paths = %q, want only configured-name expired inactive match %q", api.deletions, want)
	}
}

func TestRunCLIRetriesFailedUploadOnNextInvocation(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	api := &uploadAPIFixture{rejectUploadCount: 1, wantCert: string(certPEM), wantKey: "opaque key"}
	server := httptest.NewServer(api)
	defer server.Close()

	certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("opaque key"))
	setUploadEnvironment(t, server.URL, certFile, keyFile)
	if err := runCLI(context.Background(), nil); err == nil {
		t.Fatal("first runCLI() succeeded despite upload rejection")
	}
	if err := runCLI(context.Background(), nil); err != nil {
		t.Fatalf("second runCLI() error = %v", err)
	}
	if api.logins != 2 || api.uploads != 2 || api.activations != 1 {
		t.Errorf("API calls after retry = login:%d upload:%d activate:%d, want 2,2,1", api.logins, api.uploads, api.activations)
	}
	if api.certificateLists != 2 {
		t.Errorf("certificate lists = %d, want one before each upload attempt", api.certificateLists)
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
	if api.certificateLists != 1 {
		t.Fatalf("certificate lists = %d, want the initial ownership check", api.certificateLists)
	}
}

func TestRunCLIReusesCertificateAfterActivationFailure(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	api := &uploadAPIFixture{
		wantCert:              string(certPEM),
		wantKey:               "key",
		rejectActivationCount: 1,
	}
	server := httptest.NewServer(api)
	defer server.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("key"))
	setUploadEnvironment(t, server.URL, certFile, keyFile)

	if err := runCLI(t.Context(), nil); err == nil {
		t.Fatal("first runCLI() succeeded despite activation rejection")
	}
	if err := runCLI(t.Context(), nil); err != nil {
		t.Fatalf("second runCLI() error = %v", err)
	}
	if api.uploads != 1 || api.activations != 2 || api.certificateLists != 2 {
		t.Fatalf("API calls = upload:%d activate:%d list:%d, want 1,2,2", api.uploads, api.activations, api.certificateLists)
	}
}

func TestRunCLIReusesCertificateAfterInvalidUploadResponse(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	api := &uploadAPIFixture{
		wantCert:              string(certPEM),
		wantKey:               "key",
		invalidUploadResponse: true,
	}
	server := httptest.NewServer(api)
	defer server.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("key"))
	setUploadEnvironment(t, server.URL, certFile, keyFile)

	if err := runCLI(t.Context(), nil); err == nil {
		t.Fatal("first runCLI() succeeded despite an invalid upload response")
	}
	if err := runCLI(t.Context(), nil); err != nil {
		t.Fatalf("second runCLI() error = %v", err)
	}
	if api.uploads != 1 || api.activations != 1 || api.certificateLists != 2 {
		t.Fatalf("API calls = upload:%d activate:%d list:%d, want 1,1,2", api.uploads, api.activations, api.certificateLists)
	}
}

func TestRunCLILeavesMatchingActiveCertificateUntouched(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	api := &uploadAPIFixture{
		certificates: []UniFiCertificate{{
			ID:          "existing",
			Name:        fixtureCertificateName("fixture upload", certPEM),
			Fingerprint: strings.ToLower(fixtureCertificateFingerprint(string(certPEM))),
			Active:      fixtureBool(true),
		}},
	}
	server := httptest.NewServer(api)
	defer server.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("key"))
	setUploadEnvironment(t, server.URL, certFile, keyFile)

	if err := runCLI(t.Context(), nil); err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}
	if api.uploads != 0 || api.activations != 0 || len(api.deletions) != 0 {
		t.Fatalf("API mutations = upload:%d activate:%d delete:%d, want none", api.uploads, api.activations, len(api.deletions))
	}
}

func TestRunCLIRejectsMatchingCertificateWithoutID(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	api := &uploadAPIFixture{certificates: []UniFiCertificate{{
		Name:        fixtureCertificateName("fixture upload", certPEM),
		Fingerprint: fixtureCertificateFingerprint(string(certPEM)),
		Active:      fixtureBool(false),
	}}}
	server := httptest.NewServer(api)
	defer server.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("key"))
	setUploadEnvironment(t, server.URL, certFile, keyFile)

	err := runCLI(t.Context(), nil)
	if err == nil || !strings.Contains(err.Error(), "omitted id") {
		t.Fatalf("runCLI() error = %v, want missing id error", err)
	}
	if api.uploads != 0 || api.activations != 0 {
		t.Fatalf("matching certificate without an id mutated API: upload:%d activate:%d", api.uploads, api.activations)
	}
}

func TestRunCLIRejectsCertificateNameCollisions(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	name := fixtureCertificateName("fixture upload", certPEM)
	fingerprint := fixtureCertificateFingerprint(string(certPEM))
	differentFingerprint := fingerprint[:len(fingerprint)-2] + "00"
	if strings.HasSuffix(fingerprint, "00") {
		differentFingerprint = fingerprint[:len(fingerprint)-2] + "FF"
	}
	for _, fingerprint := range []string{differentFingerprint, "", "not-a-fingerprint"} {
		t.Run(fingerprint, func(t *testing.T) {
			api := &uploadAPIFixture{certificates: []UniFiCertificate{{
				ID:          "collision",
				Name:        name,
				Fingerprint: fingerprint,
				Active:      fixtureBool(false),
			}}}
			server := httptest.NewServer(api)
			defer server.Close()
			certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("key"))
			setUploadEnvironment(t, server.URL, certFile, keyFile)
			t.Setenv("UNIFI_CLEANUP", "true")

			err := runCLI(t.Context(), nil)
			if err == nil || !strings.Contains(err.Error(), "certificate name collision") {
				t.Fatalf("runCLI() error = %v, want collision error", err)
			}
			if api.uploads != 0 || api.activations != 0 || len(api.deletions) != 0 {
				t.Fatalf("collision mutations = upload:%d activate:%d delete:%d, want none", api.uploads, api.activations, len(api.deletions))
			}
		})
	}
}

func TestRunCLICleanupDoesNotDeleteReactivatedCertificate(t *testing.T) {
	certPEM := readCertificateFixture(t, "isrg-root-x1.pem")
	api := &uploadAPIFixture{certificates: []UniFiCertificate{{
		ID:          "expired-existing",
		Name:        fixtureCertificateName("fixture upload", certPEM),
		Fingerprint: fixtureCertificateFingerprint(string(certPEM)),
		ValidTo:     "2001-01-01T00:00:00Z",
		Active:      fixtureBool(false),
	}}}
	server := httptest.NewServer(api)
	defer server.Close()
	certFile, keyFile := writeCLIInputFiles(t, certPEM, []byte("key"))
	setUploadEnvironment(t, server.URL, certFile, keyFile)
	t.Setenv("UNIFI_CLEANUP", "true")

	if err := runCLI(t.Context(), nil); err != nil {
		t.Fatalf("runCLI() error = %v", err)
	}
	for _, deletion := range api.deletions {
		if deletion == "/api/userCertificates/expired-existing" {
			t.Fatalf("cleanup deleted the certificate activated in this run: %q", deletion)
		}
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
		"UNIFI_TARGETS":           "",
		"LEGO_HOOK_CERT_DOMAINS":  "",
	} {
		t.Setenv(name, value)
	}
}

type targetUploadEnvironment struct {
	ID              string
	Domain          string
	URL             string
	Username        string
	Password        string
	CertificateName string
	Cleanup         string
}

func setTargetUploadEnvironment(t *testing.T, target targetUploadEnvironment) {
	t.Helper()
	envBase := "UNIFI_" + target.ID
	for variable, value := range map[string]string{
		envBase + "_DOMAIN":          target.Domain,
		envBase + "_URL":             target.URL,
		envBase + "_USERNAME":        target.Username,
		envBase + "_USERNAME_FILE":   "",
		envBase + "_PASSWORD":        target.Password,
		envBase + "_PASSWORD_FILE":   "",
		envBase + "_HTTP_TIMEOUT":    "",
		envBase + "_SKIP_TLS_VERIFY": "",
		envBase + "_CERT_NAME":       target.CertificateName,
		envBase + "_CLEANUP":         target.Cleanup,
	} {
		t.Setenv(variable, value)
	}
}

type uploadAPIFixture struct {
	logins                int
	uploads               int
	activations           int
	certificateLists      int
	rejectDuplicate       bool
	rejectUploadCount     int
	rejectActivation      bool
	rejectActivationCount int
	invalidUploadResponse bool
	wantCert              string
	wantKey               string
	username              string
	password              string
	name                  string
	cleanupName           string
	deletions             []string
	certificates          []UniFiCertificate
	afterActivation       func()
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
		username := api.username
		if username == "" {
			username = "admin"
		}
		password := api.password
		if password == "" {
			password = "console-password"
		}
		if credentials.Username != username || credentials.Password != password {
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
		if api.rejectUploadCount > 0 {
			api.rejectUploadCount--
			http.Error(w, "fixture response body", http.StatusConflict)
			return
		}
		if api.rejectDuplicate && upload.Name == api.name {
			http.Error(w, "fixture response body", http.StatusConflict)
			return
		}
		api.name = upload.Name
		id := fmt.Sprintf("fixture/id-%d", api.uploads)
		api.certificates = append(api.certificates, UniFiCertificate{
			ID:          id,
			Name:        upload.Name,
			Fingerprint: fixtureCertificateFingerprint(upload.Cert),
			Active:      fixtureBool(false),
		})
		if api.invalidUploadResponse {
			api.invalidUploadResponse = false
			writeFixtureJSON(w, map[string]string{"name": upload.Name})
			return
		}
		writeFixtureJSON(w, map[string]string{"id": id})

	case r.Method == http.MethodPut && strings.HasSuffix(r.URL.EscapedPath(), "/status"):
		api.activations++
		var status struct {
			Active bool `json:"active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&status); err != nil || !status.Active {
			http.Error(w, "expected activation", http.StatusBadRequest)
			return
		}
		if api.rejectActivationCount > 0 {
			api.rejectActivationCount--
			http.Error(w, "activation rejected", http.StatusBadGateway)
			return
		}
		if api.rejectActivation {
			http.Error(w, "activation rejected", http.StatusBadGateway)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.EscapedPath(), "/api/userCertificates/"), "/status")
		id, _ = url.PathUnescape(id)
		for index := range api.certificates {
			if api.certificates[index].ID == id {
				api.certificates[index].Active = fixtureBool(true)
			}
		}
		if api.afterActivation != nil {
			api.afterActivation()
		}
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet && r.URL.Path == "/api/userCertificates":
		api.certificateLists++
		baseName := api.cleanupName
		certificates := append([]UniFiCertificate(nil), api.certificates...)
		certificates = append(certificates, []UniFiCertificate{
			{ID: "expired/match", Name: baseName + " old", ValidTo: "2001-01-01T00:00:00Z", Active: fixtureBool(false)},
			{ID: "expired/regex-neighbor", Name: strings.Replace(baseName, "[prod]", "xprod]", 1) + " old", ValidTo: "2001-01-01T00:00:00Z", Active: fixtureBool(false)},
			{ID: "expired/no-suffix", Name: baseName + " ", ValidTo: "2001-01-01T00:00:00Z", Active: fixtureBool(false)},
			{ID: "expired/active", Name: baseName + " active", ValidTo: "2001-01-01T00:00:00Z", Active: fixtureBool(true)},
			{ID: "future/inactive", Name: baseName + " future", ValidTo: "2999-01-01T00:00:00Z", Active: fixtureBool(false)},
			{ID: "invalid/expiry", Name: baseName + " invalid", ValidTo: "bad-date", Active: fixtureBool(false)},
			{ID: "unmanaged", Name: "other service old", ValidTo: "2001-01-01T00:00:00Z", Active: fixtureBool(false)},
			{ID: "unknown/active", Name: baseName + " unknown", ValidTo: "2001-01-01T00:00:00Z"},
		}...)
		writeFixtureJSON(w, certificates)

	case r.Method == http.MethodDelete:
		api.deletions = append(api.deletions, r.URL.EscapedPath())
		w.WriteHeader(http.StatusNoContent)

	default:
		http.NotFound(w, r)
	}
}

func fixtureCertificateFingerprint(certificate string) string {
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		return ""
	}
	fingerprint := sha1.Sum(block.Bytes)
	parts := make([]string, len(fingerprint))
	for index, value := range fingerprint {
		parts[index] = fmt.Sprintf("%02X", value)
	}
	return strings.Join(parts, ":")
}

func fixtureCertificateName(baseName string, certificate []byte) string {
	block, _ := pem.Decode(certificate)
	if block == nil {
		return ""
	}
	fingerprint := sha1.Sum(block.Bytes)
	return fmt.Sprintf("%s %x", baseName, fingerprint[:4])
}

func fixtureBool(value bool) *bool {
	return &value
}

func writeFixtureJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
