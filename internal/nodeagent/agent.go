package nodeagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mgb-panel/internal/secret"
	"mgb-panel/internal/singbox"
)

type Config struct {
	PanelURL           string
	StateDir           string
	BootstrapToken     string
	BootstrapTokenFile string
	PanelCAFile        string
	PanelFingerprint   string
	SingboxBinary      string
	PollInterval       time.Duration
}

type Agent struct {
	cfg     Config
	manager *singbox.Manager
	state   localState
	logger  *log.Logger
}

type localState struct {
	NodeID         string `json:"node_id"`
	CurrentRev     int    `json:"current_revision"`
	LastApplyError string `json:"last_apply_error"`
	Status         string `json:"status"`
}

func New(cfg Config) (*Agent, error) {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 20 * time.Second
	}
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir state dir: %w", err)
	}
	agent := &Agent{
		cfg:     cfg,
		manager: singbox.NewManager(cfg.SingboxBinary, filepath.Join(cfg.StateDir, "runtime")),
		logger:  log.New(os.Stdout, "node-agent ", log.LstdFlags|log.Lmsgprefix),
	}
	if err := agent.loadState(); err != nil {
		return nil, err
	}
	return agent, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.bootstrapCA(ctx); err != nil {
		return err
	}
	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}

	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()

	for {
		if err := a.reconcile(ctx); err != nil {
			a.logger.Printf("reconcile error: %v", err)
		}

		select {
		case <-ctx.Done():
			_ = a.manager.Stop()
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (a *Agent) reconcile(ctx context.Context) error {
	if err := a.sendHeartbeat(ctx); err != nil {
		return err
	}
	client, err := a.mTLSClient()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.PanelURL+"/api/node/config?current_revision="+fmt.Sprint(a.state.CurrentRev), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fetch config status %d: %s", resp.StatusCode, string(body))
	}

	var payload struct {
		NodeID   string          `json:"node_id"`
		Revision int             `json:"revision"`
		Changed  bool            `json:"changed"`
		Config   json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("decode config response: %w", err)
	}
	if !payload.Changed || len(payload.Config) == 0 {
		return nil
	}

	err = a.manager.Apply(ctx, payload.Config)
	if err != nil {
		a.state.LastApplyError = err.Error()
		a.state.Status = "error"
		_ = a.saveState()
		return a.sendAck(ctx, payload.Revision, false, err.Error())
	}

	a.state.NodeID = payload.NodeID
	a.state.CurrentRev = payload.Revision
	a.state.LastApplyError = ""
	a.state.Status = "healthy"
	if err := a.saveState(); err != nil {
		return err
	}
	return a.sendAck(ctx, payload.Revision, true, "")
}

func (a *Agent) sendHeartbeat(ctx context.Context) error {
	client, err := a.mTLSClient()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"status":   defaultStatus(a.state.Status),
		"revision": a.state.CurrentRev,
		"error":    a.state.LastApplyError,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.PanelURL+"/api/node/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat status %d: %s", resp.StatusCode, payload)
	}
	return nil
}

func (a *Agent) sendAck(ctx context.Context, revision int, success bool, message string) error {
	client, err := a.mTLSClient()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"revision": revision,
		"success":  success,
		"error":    message,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.PanelURL+"/api/node/ack", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ack request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ack status %d: %s", resp.StatusCode, payload)
	}
	return nil
}

func (a *Agent) ensureEnrolled(ctx context.Context) error {
	certPath, keyPath := a.certPath(), a.keyPath()
	if fileExists(certPath) && fileExists(keyPath) {
		return nil
	}
	bootstrapToken, err := a.bootstrapToken(ctx)
	if err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate node key: %w", err)
	}
	nodeName, err := secret.ID("bootstrap")
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: nodeName},
	}, key)
	if err != nil {
		return fmt.Errorf("create csr: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	client, err := a.bootstrapClient()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"bootstrap_token": bootstrapToken,
		"csr":             string(csrPEM),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.PanelURL+"/api/node/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("enroll request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enroll status %d: %s", resp.StatusCode, payload)
	}
	var payload struct {
		NodeID      string `json:"node_id"`
		Certificate string `json:"certificate"`
		CA          string `json:"ca"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("decode enroll response: %w", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write node key: %w", err)
	}
	if err := os.WriteFile(certPath, []byte(payload.Certificate), 0o644); err != nil {
		return fmt.Errorf("write node cert: %w", err)
	}
	if err := os.WriteFile(a.caPath(), []byte(payload.CA), 0o644); err != nil {
		return fmt.Errorf("write ca bundle: %w", err)
	}
	a.state.NodeID = payload.NodeID
	a.state.Status = "enrolled"
	return a.saveState()
}

func (a *Agent) bootstrapCA(ctx context.Context) error {
	if a.cfg.PanelCAFile != "" {
		for {
			if fileExists(a.cfg.PanelCAFile) {
				data, err := os.ReadFile(a.cfg.PanelCAFile)
				if err != nil {
					return err
				}
				return os.WriteFile(a.caPath(), data, 0o644)
			}
			if a.cfg.PanelFingerprint != "" {
				break
			}
			a.logger.Printf("waiting for panel CA file %s", a.cfg.PanelCAFile)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	if fileExists(a.caPath()) {
		return nil
	}
	if a.cfg.PanelFingerprint == "" {
		return fmt.Errorf("panel CA file or panel fingerprint is required for bootstrap")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.PanelURL+"/api/pki/ca", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download ca: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download ca status %d: %s", resp.StatusCode, body)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fp, err := pemFingerprint(data)
	if err != nil {
		return err
	}
	if !strings.EqualFold(fp, strings.TrimSpace(a.cfg.PanelFingerprint)) {
		return fmt.Errorf("panel CA fingerprint mismatch")
	}
	return os.WriteFile(a.caPath(), data, 0o644)
}

func (a *Agent) bootstrapToken(ctx context.Context) (string, error) {
	if token := strings.TrimSpace(a.cfg.BootstrapToken); token != "" {
		return token, nil
	}
	if a.cfg.BootstrapTokenFile == "" {
		return "", fmt.Errorf("bootstrap token or bootstrap token file is required")
	}
	for {
		data, err := os.ReadFile(a.cfg.BootstrapTokenFile)
		if err == nil {
			if token := strings.TrimSpace(string(data)); token != "" {
				return token, nil
			}
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("read bootstrap token file: %w", err)
		}
		a.logger.Printf("waiting for bootstrap token file %s", a.cfg.BootstrapTokenFile)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *Agent) bootstrapClient() (*http.Client, error) {
	caBytes, err := os.ReadFile(a.caPath())
	if err != nil {
		return nil, fmt.Errorf("read ca bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("append ca bundle")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    pool,
		},
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}, nil
}

func (a *Agent) mTLSClient() (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(a.certPath(), a.keyPath())
	if err != nil {
		return nil, fmt.Errorf("load node keypair: %w", err)
	}
	caBytes, err := os.ReadFile(a.caPath())
	if err != nil {
		return nil, fmt.Errorf("read ca bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("append ca bundle")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
		},
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}, nil
}

func (a *Agent) loadState() error {
	path := a.statePath()
	if !fileExists(path) {
		a.state = localState{Status: "pending"}
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read state file: %w", err)
	}
	if err := json.Unmarshal(data, &a.state); err != nil {
		return fmt.Errorf("decode state file: %w", err)
	}
	return nil
}

func (a *Agent) saveState() error {
	data, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return os.WriteFile(a.statePath(), data, 0o600)
}

func (a *Agent) statePath() string {
	return filepath.Join(a.cfg.StateDir, "state.json")
}

func (a *Agent) certPath() string {
	return filepath.Join(a.cfg.StateDir, "node-cert.pem")
}

func (a *Agent) keyPath() string {
	return filepath.Join(a.cfg.StateDir, "node-key.pem")
}

func (a *Agent) caPath() string {
	return filepath.Join(a.cfg.StateDir, "panel-ca.pem")
}

func defaultStatus(status string) string {
	if status == "" {
		return "healthy"
	}
	return status
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func pemFingerprint(data []byte) (string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("decode pem")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
