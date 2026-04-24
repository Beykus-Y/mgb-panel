package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mgb-panel/internal/nodeagent"
)

func main() {
	var (
		panelURL         = flag.String("panel-url", "https://localhost:8443", "panel base URL")
		stateDir         = flag.String("state-dir", "./var/node", "node state directory")
		bootstrapToken   = flag.String("bootstrap-token", "", "bootstrap token issued by the panel")
		panelCAFile      = flag.String("panel-ca-file", "", "path to panel CA certificate bundle")
		panelFingerprint = flag.String("panel-fingerprint", "", "expected panel CA SHA-256 fingerprint")
		singboxBinary    = flag.String("singbox-binary", "sing-box", "path to sing-box binary")
		pollInterval     = flag.Duration("poll-interval", 20*time.Second, "poll interval")
	)
	flag.Parse()

	agent, err := nodeagent.New(nodeagent.Config{
		PanelURL:         *panelURL,
		StateDir:         *stateDir,
		BootstrapToken:   *bootstrapToken,
		PanelCAFile:      *panelCAFile,
		PanelFingerprint: *panelFingerprint,
		SingboxBinary:    *singboxBinary,
		PollInterval:     *pollInterval,
	})
	if err != nil {
		log.Fatalf("build node agent: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := agent.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("run node agent: %v", err)
	}
}
