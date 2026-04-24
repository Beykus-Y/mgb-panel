package singbox

import (
	"context"
	"io"
	"os/exec"
	"testing"
)

type stubRunner struct {
	runErr   error
	startErr error
}

func (s stubRunner) Run(ctx context.Context, name string, args ...string) error {
	return s.runErr
}

func (s stubRunner) Start(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, "bash", "-lc", "sleep 1")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, s.startErr
}

func TestManagerValidateAndApply(t *testing.T) {
	mgr := NewManager("sing-box", t.TempDir())
	mgr.SetRunner(stubRunner{})
	cfg := []byte(`{"log":{"level":"info"}}`)

	if err := mgr.Validate(context.Background(), cfg); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := mgr.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestManagerValidateFailure(t *testing.T) {
	mgr := NewManager("sing-box", t.TempDir())
	mgr.SetRunner(stubRunner{runErr: context.DeadlineExceeded})
	if err := mgr.Validate(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("expected validate error")
	}
}
