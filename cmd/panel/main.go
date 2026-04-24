package main

import (
	"context"
	"flag"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mgb-panel/internal/controlplane"
	"mgb-panel/internal/database"
	"mgb-panel/internal/nodeagent"
	"mgb-panel/internal/pki"
)

func main() {
	var (
		listenAddr      = flag.String("listen", ":8443", "HTTPS listen address")
		baseURL         = flag.String("base-url", "https://localhost:8443", "public base URL")
		dataDir         = flag.String("data-dir", "./var/panel", "panel data directory")
		enableLocalNode = flag.Bool("enable-local-node", false, "run node-agent in the same process")
		localNodeToken  = flag.String("local-node-token", "", "bootstrap token for embedded node-agent")
		singboxBinary   = flag.String("singbox-binary", "sing-box", "path to sing-box binary")
		localNodePoll   = flag.Duration("local-node-poll", 20*time.Second, "embedded node-agent poll interval")
	)
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatalf("mkdir data dir: %v", err)
	}

	store, err := database.Open(filepath.Join(*dataDir, "panel.db"))
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	panelHost := "mgb-panel"
	if parsed, parseErr := url.Parse(*baseURL); parseErr == nil {
		panelHost = parsed.Hostname()
	}
	if panelHost == "" {
		panelHost = "mgb-panel"
	}
	authority, err := pki.LoadOrCreate(filepath.Join(*dataDir, "pki"), panelHost)
	if err != nil {
		log.Fatalf("load pki: %v", err)
	}

	server, err := controlplane.New(store, authority, controlplane.Config{
		ListenAddr: *listenAddr,
		BaseURL:    *baseURL,
	})
	if err != nil {
		log.Fatalf("build server: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *enableLocalNode {
		if *localNodeToken == "" {
			log.Fatal("local node requested but -local-node-token is empty")
		}
		agent, err := nodeagent.New(nodeagent.Config{
			PanelURL:         strings.TrimRight(*baseURL, "/"),
			StateDir:         filepath.Join(*dataDir, "local-node"),
			BootstrapToken:   *localNodeToken,
			PanelCAFile:      filepath.Join(*dataDir, "pki", "ca.pem"),
			SingboxBinary:    *singboxBinary,
			PollInterval:     *localNodePoll,
			PanelFingerprint: authority.FingerprintHex(),
		})
		if err != nil {
			log.Fatalf("build local node agent: %v", err)
		}
		go func() {
			if err := agent.Run(ctx); err != nil && err != context.Canceled {
				log.Printf("local node agent stopped: %v", err)
			}
		}()
	}

	go func() {
		log.Printf("panel listening on %s", *listenAddr)
		if err := server.ListenAndServeTLS(); err != nil && err.Error() != "http: Server closed" {
			log.Fatalf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}
