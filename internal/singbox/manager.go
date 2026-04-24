package singbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
	Start(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) (*exec.Cmd, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(output))
	}
	return nil
}

func (ExecRunner) Start(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

type Manager struct {
	BinaryPath      string
	WorkDir         string
	ActiveConfig    string
	CandidateConfig string
	LastGoodConfig  string
	LogPath         string

	runner CommandRunner
	mu     sync.Mutex
	cmd    *exec.Cmd
}

func NewManager(binaryPath, workDir string) *Manager {
	return &Manager{
		BinaryPath:      binaryPath,
		WorkDir:         workDir,
		ActiveConfig:    filepath.Join(workDir, "sing-box.json"),
		CandidateConfig: filepath.Join(workDir, "sing-box.candidate.json"),
		LastGoodConfig:  filepath.Join(workDir, "sing-box.last-good.json"),
		LogPath:         filepath.Join(workDir, "sing-box.log"),
		runner:          ExecRunner{},
	}
}

func (m *Manager) SetRunner(runner CommandRunner) {
	m.runner = runner
}

func (m *Manager) Validate(ctx context.Context, config []byte) error {
	if err := m.writeCandidate(config); err != nil {
		return err
	}
	return m.runner.Run(ctx, m.BinaryPath, "check", "-c", m.CandidateConfig)
}

func (m *Manager) Apply(ctx context.Context, config []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.WorkDir, 0o755); err != nil {
		return fmt.Errorf("mkdir work dir: %w", err)
	}
	if err := m.writeCandidate(config); err != nil {
		return err
	}
	if err := m.runner.Run(ctx, m.BinaryPath, "check", "-c", m.CandidateConfig); err != nil {
		return err
	}
	if err := backupIfExists(m.ActiveConfig, m.LastGoodConfig); err != nil {
		return err
	}
	if err := os.Rename(m.CandidateConfig, m.ActiveConfig); err != nil {
		return fmt.Errorf("activate candidate config: %w", err)
	}
	if err := m.restart(ctx); err != nil {
		if restoreErr := backupIfExists(m.LastGoodConfig, m.ActiveConfig); restoreErr != nil {
			return fmt.Errorf("restart failed: %v; restore failed: %w", err, restoreErr)
		}
		if secondErr := m.restart(ctx); secondErr != nil {
			return fmt.Errorf("restart failed: %v; rollback restart failed: %w", err, secondErr)
		}
		return err
	}
	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}
	if err := m.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("kill sing-box: %w", err)
	}
	_, _ = m.cmd.Process.Wait()
	m.cmd = nil
	return nil
}

func (m *Manager) writeCandidate(config []byte) error {
	if err := os.MkdirAll(m.WorkDir, 0o755); err != nil {
		return fmt.Errorf("mkdir work dir: %w", err)
	}
	if err := os.WriteFile(m.CandidateConfig, config, 0o600); err != nil {
		return fmt.Errorf("write candidate config: %w", err)
	}
	return nil
}

func (m *Manager) restart(ctx context.Context) error {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_, _ = m.cmd.Process.Wait()
		m.cmd = nil
	}

	logFile, err := os.OpenFile(m.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open sing-box log: %w", err)
	}
	cmd, err := m.runner.Start(ctx, logFile, logFile, m.BinaryPath, "run", "-c", m.ActiveConfig)
	if err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start sing-box: %w", err)
	}
	m.cmd = cmd

	time.Sleep(500 * time.Millisecond)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return fmt.Errorf("sing-box exited immediately")
	}
	return nil
}

func backupIfExists(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", src, err)
	}
	if err := os.WriteFile(dst, input, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}
