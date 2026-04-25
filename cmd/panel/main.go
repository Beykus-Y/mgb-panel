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
	"mgb-panel/internal/pki"
)

func main() {
	var (
		listenAddr      = flag.String("listen", ":8443", "HTTPS listen address")
		baseURL         = flag.String("base-url", "https://localhost:8443", "public base URL")
		dataDir         = flag.String("data-dir", "./var/panel", "panel data directory")
		enableLocalNode = flag.Bool("enable-local-node", false, "provision a local node record for a separate node-agent container")
		localNodeToken  = flag.String("local-node-token", "", "bootstrap token for the local node-agent container")
		singboxBinary   = flag.String("singbox-binary", "sing-box", "path to sing-box binary")
		localNodePoll   = flag.Duration("local-node-poll", 20*time.Second, "local node-agent poll interval")
		adminUser       = flag.String("admin-user", "admin", "admin username for Basic Auth")
		adminPassword   = flag.String("admin-password", "", "admin password for Basic Auth")
		adminPassFile   = flag.String("admin-password-file", "", "path to admin password file for Basic Auth")
	)
	flag.Parse()
	adminPass, err := loadAdminPassword(*adminPassword, *adminPassFile)
	if err != nil {
		log.Fatalf("load admin password: %v", err)
	}

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
		ListenAddr:    *listenAddr,
		BaseURL:       *baseURL,
		DataDir:       *dataDir,
		SingboxBinary: *singboxBinary,
		LocalPoll:     *localNodePoll,
		AdminUser:     *adminUser,
		AdminPassword: adminPass,
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
		if _, err := store.EnsureLocalNode(ctx, *localNodeToken); err != nil {
			log.Fatalf("ensure local node: %v", err)
		}
		if err := writeLocalNodeBootstrapToken(*dataDir, *localNodeToken); err != nil {
			log.Fatalf("write local node bootstrap token: %v", err)
		}
		log.Printf("local node record is ready; node-agent is expected to run as a separate container")
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

func writeLocalNodeBootstrapToken(dataDir, token string) error {
	dir := filepath.Join(dataDir, "local-node")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "bootstrap-token"), []byte(strings.TrimSpace(token)+"\n"), 0o600)
}

func loadAdminPassword(value, filePath string) (string, error) {
	if strings.TrimSpace(filePath) != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(data))
	}
	if value == "" {
		return "", os.ErrInvalid
	}
	return value, nil
}
