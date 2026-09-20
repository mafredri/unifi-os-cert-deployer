package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const maxUniFiResponseBytes = 4 << 20

type UniFiConfig struct {
	URL           string
	Username      string
	Password      string
	HTTPTimeout   time.Duration
	SkipTLSVerify bool
}

type UniFiClient struct {
	baseURL   string
	http      *http.Client
	username  string
	password  string
	csrfToken string
}

func NewUniFiClient(cfg UniFiConfig) (*UniFiClient, error) {
	rawURL := strings.TrimSpace(cfg.URL)
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("UniFi URL is invalid")
	}
	if !parsedURL.IsAbs() {
		return nil, errors.New("UniFi URL must be absolute")
	}
	if parsedURL.Opaque != "" {
		return nil, errors.New("UniFi URL must use a hierarchical origin")
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	switch scheme {
	case "http", "https":
	default:
		return nil, errors.New("UniFi URL scheme must be http or https")
	}
	if parsedURL.Hostname() == "" {
		return nil, errors.New("UniFi URL must include a host")
	}
	if parsedURL.User != nil {
		return nil, errors.New("UniFi URL credentials are not allowed")
	}
	if parsedURL.Path != "" && parsedURL.Path != "/" {
		return nil, errors.New("UniFi URL must be a console root URL")
	}
	if parsedURL.RawQuery != "" || parsedURL.ForceQuery {
		return nil, errors.New("UniFi URL query is not allowed")
	}
	if strings.Contains(rawURL, "#") {
		return nil, errors.New("UniFi URL fragment is not allowed")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create UniFi cookie jar: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// #nosec G402: skipping verification is an explicit operator setting for self-signed consoles.
		InsecureSkipVerify: cfg.SkipTLSVerify,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.HTTPTimeout,
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseURL := url.URL{Scheme: scheme, Host: parsedURL.Host}
	return &UniFiClient{
		baseURL: baseURL.String(), http: client, username: cfg.Username, password: cfg.Password,
	}, nil
}

func (c *UniFiClient) Login(ctx context.Context) error {
	c.csrfToken = ""
	credentials := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{Username: c.username, Password: c.password}
	return c.requestJSON(ctx, http.MethodPost, "/api/auth/login", credentials, nil, "login")
}

func (c *UniFiClient) UploadCertificate(ctx context.Context, name string, certPEM, keyPEM []byte) (string, error) {
	request := struct {
		Name string `json:"name"`
		Key  string `json:"key"`
		Cert string `json:"cert"`
	}{Name: name, Key: string(keyPEM), Cert: string(certPEM)}
	var response struct {
		ID string `json:"id"`
	}
	if err := c.requestJSON(ctx, http.MethodPost, "/api/userCertificates", request, &response, "upload certificate"); err != nil {
		return "", err
	}
	if response.ID == "" {
		return "", errors.New("upload certificate response omitted id")
	}
	return response.ID, nil
}

func (c *UniFiClient) ActivateCertificate(ctx context.Context, id string) error {
	request := struct {
		Active bool `json:"active"`
	}{Active: true}
	path := "/api/userCertificates/" + escapeIDPathSegment(id) + "/status"
	return c.requestJSON(ctx, http.MethodPut, path, request, nil, "activate certificate")
}

type UniFiCertificate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	ValidTo     string `json:"valid_to"`
	Active      *bool  `json:"active"`
}

func (c *UniFiClient) ListCertificates(ctx context.Context) ([]UniFiCertificate, error) {
	var certificates []UniFiCertificate
	if err := c.requestJSON(ctx, http.MethodGet, "/api/userCertificates", nil, &certificates, "list certificates"); err != nil {
		return nil, err
	}
	return certificates, nil
}

func (c *UniFiClient) DeleteCertificate(ctx context.Context, id string) error {
	path := "/api/userCertificates/" + escapeIDPathSegment(id)
	return c.requestJSON(ctx, http.MethodDelete, path, nil, nil, "delete certificate")
}

func escapeIDPathSegment(id string) string {
	escaped := url.PathEscape(id)
	if id == "." || id == ".." {
		return strings.Repeat("%2E", len(id))
	}
	return escaped
}

func (c *UniFiClient) requestJSON(ctx context.Context, method, path string, requestBody, responseBody any, operation string) error {
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encode %s request: %w", operation, err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create %s request: %w", operation, err)
	}
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	defer resp.Body.Close()
	if token := responseCSRFToken(resp); token != "" {
		c.csrfToken = token
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxUniFiResponseBytes))
		return fmt.Errorf("%s returned HTTP %s", operation, resp.Status)
	}
	if responseBody == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxUniFiResponseBytes))
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxUniFiResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read %s response: %w", operation, err)
	}
	if len(data) > maxUniFiResponseBytes {
		return fmt.Errorf("%s response exceeded %d bytes", operation, maxUniFiResponseBytes)
	}
	if err := json.Unmarshal(data, responseBody); err != nil {
		return fmt.Errorf("decode %s response: %w", operation, err)
	}
	return nil
}

func responseCSRFToken(resp *http.Response) string {
	for _, header := range []string{"X-Updated-CSRF-Token", "X-CSRF-Token"} {
		if token := resp.Header.Get(header); token != "" {
			return token
		}
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name != "TOKEN" {
			continue
		}
		parts := strings.Split(cookie.Value, ".")
		if len(parts) != 3 {
			continue
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			continue
		}
		// Read the server-issued CSRF value; authentication remains the server's responsibility.
		var claims struct {
			CSRFToken string `json:"csrfToken"`
		}
		if json.Unmarshal(payload, &claims) == nil {
			return claims.CSRFToken
		}
	}
	return ""
}
