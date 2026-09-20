package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeployHookKeepsFailedUploadPendingUntilRetrySucceeds(t *testing.T) {
	tempDir := t.TempDir()
	legoPath := filepath.Join(tempDir, "lego data")
	uploadLog := filepath.Join(tempDir, "uploads.log")
	failFile := filepath.Join(tempDir, "fail-upload")
	certificateContents := "opaque certificate from renewal"
	keyContents := "opaque private key from renewal"

	uploader := writeTestExecutable(t, tempDir, "unifi-cert-upload", `#!/bin/sh
set -eu
[ "$#" -eq 4 ] && [ "$1" = "--cert" ] && [ "$3" = "--key" ]
printf '%s\n' "$LEGO_HOOK_CERT_DOMAINS" >> "$UPLOAD_LOG"
cat "$2" >> "$UPLOAD_LOG"
printf '\n' >> "$UPLOAD_LOG"
cat "$4" >> "$UPLOAD_LOG"
printf '\n' >> "$UPLOAD_LOG"
if [ -f "$UPLOAD_FAIL_FILE" ]; then
	exit 23
fi
`)
	pending := copyRuntimeScript(t, "deploy-pending.sh", tempDir, map[string]string{
		"/usr/local/bin/unifi-cert-upload": uploader,
	})
	hook := copyRuntimeScript(t, "lego-deploy-hook.sh", tempDir, map[string]string{
		"/usr/local/bin/deploy-pending": pending,
	})

	sourceDirectory := filepath.Join(tempDir, "renewal files")
	if err := os.MkdirAll(sourceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(sourceDirectory, "console.crt")
	keyPath := filepath.Join(sourceDirectory, "console.key")
	if err := os.WriteFile(certPath, []byte(certificateContents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyContents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(failFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	environment := map[string]string{
		"LEGO_PATH":               legoPath,
		"LEGO_HOOK_CERT_PATH":     certPath,
		"LEGO_HOOK_CERT_KEY_PATH": keyPath,
		"LEGO_DOMAINS":            "console.example, shared.example",
		"UPLOAD_LOG":              uploadLog,
		"UPLOAD_FAIL_FILE":        failFile,
	}

	if _, err := runTestScript(t, hook, environment); err == nil {
		t.Fatal("deploy hook succeeded when the uploader failed")
	}
	wantAttempt := "console.example, shared.example\n" + certificateContents + "\n" + keyContents + "\n"
	if got := readTestFile(t, uploadLog); got != wantAttempt {
		t.Fatalf("first queued upload = %q, want %q", got, wantAttempt)
	}
	pendingDirectory := filepath.Join(legoPath, "deploy", "console")
	if got := readTestFile(t, filepath.Join(pendingDirectory, "fullchain.pem")); got != certificateContents {
		t.Fatalf("queued certificate = %q, want %q", got, certificateContents)
	}
	if got := readTestFile(t, filepath.Join(pendingDirectory, "key.pem")); got != keyContents {
		t.Fatalf("queued key = %q, want %q", got, keyContents)
	}

	if err := os.WriteFile(certPath, []byte("new certificate after hook"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("new key after hook"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(failFile); err != nil {
		t.Fatal(err)
	}
	if output, err := runTestScript(t, pending, environment); err != nil {
		t.Fatalf("retry pending deployment: %v\n%s", err, output)
	}
	if got := readTestFile(t, uploadLog); got != wantAttempt+wantAttempt {
		t.Fatalf("upload attempts = %q, want the original queued files twice", got)
	}
	if _, err := os.Stat(pendingDirectory); !os.IsNotExist(err) {
		t.Fatalf("pending directory remains after success: stat error = %v", err)
	}

	if output, err := runTestScript(t, pending, environment); err != nil {
		t.Fatalf("second retry: %v\n%s", err, output)
	}
	if got := readTestFile(t, uploadLog); got != wantAttempt+wantAttempt {
		t.Fatalf("successful deployment was uploaded again: log = %q", got)
	}
}

func TestDeployPendingContinuesAfterOneUploadFails(t *testing.T) {
	tempDir := t.TempDir()
	legoPath := filepath.Join(tempDir, "lego")
	uploadLog := filepath.Join(tempDir, "uploads.log")

	uploader := writeTestExecutable(t, tempDir, "unifi-cert-upload", `#!/bin/sh
set -eu
contents=$(cat "$2")
printf '%s|%s\n' "$LEGO_HOOK_CERT_DOMAINS" "$contents" >> "$UPLOAD_LOG"
if [ "${UPLOAD_FAIL_ALL:-}" = "1" ] || [ "$contents" = "${UPLOAD_FAIL_CONTENTS:-}" ]; then
	exit 24
fi
`)
	pending := copyRuntimeScript(t, "deploy-pending.sh", tempDir, map[string]string{
		"/usr/local/bin/unifi-cert-upload": uploader,
	})
	hook := copyRuntimeScript(t, "lego-deploy-hook.sh", tempDir, map[string]string{
		"/usr/local/bin/deploy-pending": pending,
	})
	sourceDirectory := filepath.Join(tempDir, "certificates")
	if err := os.MkdirAll(sourceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	firstCert := filepath.Join(sourceDirectory, "first.crt")
	secondCert := filepath.Join(sourceDirectory, "second.crt")
	if err := os.WriteFile(firstCert, []byte("first certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(strings.TrimSuffix(firstCert, ".crt")+".key", []byte("first key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondCert, []byte("second certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(strings.TrimSuffix(secondCert, ".crt")+".key", []byte("second key"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, certPath := range []string{firstCert, secondCert} {
		environment := map[string]string{
			"LEGO_PATH":               legoPath,
			"LEGO_HOOK_CERT_PATH":     certPath,
			"LEGO_HOOK_CERT_KEY_PATH": strings.TrimSuffix(certPath, ".crt") + ".key",
			"LEGO_FIRST_DOMAINS":      "first.example",
			"LEGO_SECOND_DOMAINS":     "second.example",
			"UPLOAD_LOG":              uploadLog,
			"UPLOAD_FAIL_ALL":         "1",
		}
		if _, err := runTestScript(t, hook, environment); err == nil {
			t.Fatalf("deploy hook for %q succeeded while staging a failed upload", certPath)
		}
	}
	if err := os.WriteFile(uploadLog, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	environment := map[string]string{
		"LEGO_PATH":            legoPath,
		"LEGO_FIRST_DOMAINS":   "first.example",
		"LEGO_SECOND_DOMAINS":  "second.example",
		"UPLOAD_LOG":           uploadLog,
		"UPLOAD_FAIL_CONTENTS": "first certificate",
	}
	if _, err := runTestScript(t, pending, environment); err == nil {
		t.Fatal("deploy-pending succeeded when one upload failed")
	}
	if got, want := readTestFile(t, uploadLog), "first.example|first certificate\nsecond.example|second certificate\n"; got != want {
		t.Fatalf("attempted uploads = %q, want %q", got, want)
	}
	pendingDirectories := matchingFiles(t, filepath.Join(legoPath, "deploy", "*"))
	if len(pendingDirectories) != 1 || filepath.Base(pendingDirectories[0]) != "first" {
		t.Fatalf("pending deployment directories = %v, want only first", pendingDirectories)
	}
}

func TestRunLegoJobsKeepsJobDomainsIsolated(t *testing.T) {
	tempDir := t.TempDir()
	legoLog := filepath.Join(tempDir, "lego.log")
	lego := writeTestExecutable(t, tempDir, "lego", `#!/bin/sh
set -eu
[ "$#" -eq 1 ] && [ "$1" = "run" ]
printf '%s|%s\n' "$LEGO_CERT_NAME" "$LEGO_DOMAINS" >> "$LEGO_LOG"
`)
	deployPending := writeTestExecutable(t, tempDir, "deploy-pending", `#!/bin/sh
exit 0
`)
	runner := copyRuntimeScript(t, "lego-jobs.sh", tempDir, map[string]string{
		"/lego":                         lego,
		"/usr/local/bin/deploy-pending": deployPending,
	})
	environment := map[string]string{
		"LEGO_LOG":             legoLog,
		"LEGO_CERTIFICATES":    "home, protect",
		"LEGO_HOME_DOMAINS":    "shared.example, home.example",
		"LEGO_PROTECT_DOMAINS": "shared.example, protect.example",
		"LEGO_CERT_NAME":       "existing-name",
		"LEGO_DOMAINS":         "existing.example",
	}

	if output, err := runTestScript(t, runner, environment); err != nil {
		t.Fatalf("run certificate jobs: %v\n%s", err, output)
	}
	want := "home|shared.example, home.example\nprotect|shared.example, protect.example\n"
	if got := readTestFile(t, legoLog); got != want {
		t.Fatalf("lego job environments = %q, want %q", got, want)
	}
}

func TestRunLegoJobsPreservesNativeLegoEnvironmentWithoutJobs(t *testing.T) {
	tempDir := t.TempDir()
	legoLog := filepath.Join(tempDir, "lego.log")
	lego := writeTestExecutable(t, tempDir, "lego", `#!/bin/sh
set -eu
printf '%s|%s|%s\n' "$#:$1" "$LEGO_CERT_NAME" "$LEGO_DOMAINS" >> "$LEGO_LOG"
`)
	deployPending := writeTestExecutable(t, tempDir, "deploy-pending", `#!/bin/sh
exit 0
`)
	runner := copyRuntimeScript(t, "lego-jobs.sh", tempDir, map[string]string{
		"/lego":                         lego,
		"/usr/local/bin/deploy-pending": deployPending,
	})
	environment := map[string]string{
		"LEGO_LOG":          legoLog,
		"LEGO_CERTIFICATES": " , , ",
		"LEGO_CERT_NAME":    "native-name",
		"LEGO_DOMAINS":      "first.example, second.example",
	}

	if output, err := runTestScript(t, runner, environment); err != nil {
		t.Fatalf("run native lego job: %v\n%s", err, output)
	}
	want := "1:run|native-name|first.example, second.example\n"
	if got := readTestFile(t, legoLog); got != want {
		t.Fatalf("native lego environment = %q, want %q", got, want)
	}
}

func TestRunLegoJobsReportsMissingDomainsAndContinues(t *testing.T) {
	tempDir := t.TempDir()
	legoLog := filepath.Join(tempDir, "lego.log")
	runner := testJobRunner(t, tempDir)
	environment := map[string]string{
		"LEGO_LOG":             legoLog,
		"LEGO_CERTIFICATES":    "home,protect",
		"LEGO_PROTECT_DOMAINS": "protect.example",
	}

	output, err := runTestScript(t, runner, environment)
	if err == nil {
		t.Fatal("runner accepted a job without its domains variable")
	}
	if !strings.Contains(string(output), "LEGO_HOME_DOMAINS") {
		t.Fatalf("missing domains error = %q, want the missing setting", output)
	}
	if got := readTestFile(t, legoLog); !strings.Contains(got, "protect") {
		t.Fatalf("lego calls = %q, want the remaining protect job", got)
	}
}

func TestRunLegoJobsRetriesPendingDeploymentsAfterLegoFails(t *testing.T) {
	tempDir := t.TempDir()
	orderLog := filepath.Join(tempDir, "order.log")
	lego := writeTestExecutable(t, tempDir, "lego", `#!/bin/sh
printf 'lego\n' >> "$ORDER_LOG"
exit 25
`)
	deployPending := writeTestExecutable(t, tempDir, "deploy-pending", `#!/bin/sh
printf 'pending\n' >> "$ORDER_LOG"
`)
	runner := copyRuntimeScript(t, "lego-jobs.sh", tempDir, map[string]string{
		"/lego":                         lego,
		"/usr/local/bin/deploy-pending": deployPending,
	})
	environment := map[string]string{
		"ORDER_LOG":         orderLog,
		"LEGO_CERTIFICATES": "home",
		"LEGO_HOME_DOMAINS": "home.example",
	}

	if _, err := runTestScript(t, runner, environment); err == nil {
		t.Fatal("runner succeeded after lego failed")
	}
	if got, want := readTestFile(t, orderLog), "lego\npending\n"; got != want {
		t.Fatalf("command order = %q, want %q", got, want)
	}
}

func TestEntrypointRetriesPendingDeploymentsBeforeCertificateJobs(t *testing.T) {
	tempDir := t.TempDir()
	orderLog := filepath.Join(tempDir, "order.log")
	cronFile := filepath.Join(tempDir, "root.cron")
	deployPending := writeTestExecutable(t, tempDir, "deploy-pending", `#!/bin/sh
printf 'pending\n' >> "$ORDER_LOG"
`)
	runner := writeTestExecutable(t, tempDir, "run-lego-jobs", `#!/bin/sh
printf 'jobs\n' >> "$ORDER_LOG"
`)
	writeTestExecutable(t, tempDir, "crond", `#!/bin/sh
printf 'crond %s\n' "$*" >> "$ORDER_LOG"
`)
	entrypoint := copyRuntimeScript(t, "docker-entrypoint.sh", tempDir, map[string]string{
		"/usr/local/bin/deploy-pending": deployPending,
		"/usr/local/bin/run-lego-jobs":  runner,
		"/etc/crontabs/root":            cronFile,
	})
	environment := map[string]string{
		"PATH":          tempDir + ":/usr/bin:/bin",
		"ORDER_LOG":     orderLog,
		"CRON_SCHEDULE": "0 0 * * *",
	}

	if output, err := runTestScript(t, entrypoint, environment); err != nil {
		t.Fatalf("run entrypoint: %v\n%s", err, output)
	}
	if got, want := readTestFile(t, orderLog), "pending\njobs\ncrond -f -l 2\n"; got != want {
		t.Fatalf("startup command order = %q, want %q", got, want)
	}
	if got, want := readTestFile(t, cronFile), "0 0 * * * "+runner+"\n"; got != want {
		t.Fatalf("cron entry = %q, want %q", got, want)
	}
}

func testJobRunner(t *testing.T, tempDir string) string {
	t.Helper()
	lego := writeTestExecutable(t, tempDir, "lego", `#!/bin/sh
printf '%s\n' "$LEGO_CERT_NAME" >> "$LEGO_LOG"
`)
	deployPending := writeTestExecutable(t, tempDir, "deploy-pending", `#!/bin/sh
exit 0
`)
	return copyRuntimeScript(t, "lego-jobs.sh", tempDir, map[string]string{
		"/lego":                         lego,
		"/usr/local/bin/deploy-pending": deployPending,
	})
}

func copyRuntimeScript(t *testing.T, name, tempDir string, replacements map[string]string) string {
	t.Helper()
	sourcePath := filepath.Join("..", "..", "scripts", name)
	contents, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	text := string(contents)
	for old, replacement := range replacements {
		if !strings.Contains(text, old) {
			t.Fatalf("%s does not contain runtime path %q", sourcePath, old)
		}
		text = strings.ReplaceAll(text, old, replacement)
	}
	destination := filepath.Join(tempDir, name)
	if err := os.WriteFile(destination, []byte(text), 0o700); err != nil {
		t.Fatalf("write test copy of %s: %v", name, err)
	}
	return destination
}

func writeTestExecutable(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatalf("write test executable %s: %v", name, err)
	}
	return path
}

func runTestScript(t *testing.T, script string, environment map[string]string) (string, error) {
	t.Helper()
	command := exec.CommandContext(t.Context(), script)
	path := "/usr/bin:/bin"
	if configuredPath, ok := environment["PATH"]; ok {
		path = configuredPath
	}
	command.Env = []string{"PATH=" + path}
	for name, value := range environment {
		if name == "PATH" {
			continue
		}
		command.Env = append(command.Env, name+"="+value)
	}
	output, err := command.CombinedOutput()
	return string(output), err
}

func matchingFiles(t *testing.T, pattern string) []string {
	t.Helper()
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %q: %v", pattern, err)
	}
	return files
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}
