package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"mgb-panel/internal/model"
	"mgb-panel/internal/secret"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

type CreateNodeParams struct {
	Name    string
	Address string
	Role    string
	IsLocal bool
}

type CreateUserParams struct {
	Name     string
	Email    string
	Telegram string
	Note     string
}

type CreateSubscriptionParams struct {
	UserID    string
	Name      string
	ExpiresAt time.Time
}

type CreateInboundProfileParams struct {
	Name                   string
	Protocol               string
	ListenHost             string
	ListenPort             int
	Transport              string
	ServerName             string
	PublicHost             string
	Path                   string
	Password               string
	RealityPubKey          string
	RealityPrivateKey     string
	RealityHandshakeServer string
	RealityHandshakePort   int
	RealityShort           string
	TLSMode                string
	TLSCertPath            string
	TLSKeyPath             string
	ShadowsocksMethod      string
	Metadata               map[string]string
}

type CreateTopologyLinkParams struct {
	SourceNodeID string
	TargetNodeID string
	Role         string
	Transport    string
	ListenPort   int
	EndpointHost string
	EndpointPort int
	AllowedCIDRs string
}

type PortalData struct {
	User         model.User
	Subscription model.Subscription
	Nodes        []model.Node
	Inbounds     []model.InboundProfile
	Bindings     []model.NodeInboundBinding
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir db dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.seedDefaults(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS admins (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			email TEXT NOT NULL,
			telegram TEXT NOT NULL DEFAULT '',
			note TEXT NOT NULL DEFAULT '',
			access_key TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			modified_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS subscriptions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			status TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL,
			modified_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS subscription_tokens (
			id TEXT PRIMARY KEY,
			subscription_id TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			address TEXT NOT NULL DEFAULT '',
			is_local BOOLEAN NOT NULL DEFAULT 0,
			role TEXT NOT NULL,
			status TEXT NOT NULL,
			last_heartbeat TIMESTAMP,
			last_seen_ip TEXT NOT NULL DEFAULT '',
			active_revision INTEGER NOT NULL DEFAULT 0,
			last_apply_error TEXT NOT NULL DEFAULT '',
			cert_serial TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS node_enroll_tokens (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			used_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS node_certificates (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			serial TEXT NOT NULL,
			pem TEXT NOT NULL,
			not_after TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS node_status (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL UNIQUE,
			reported_status TEXT NOT NULL,
			last_error TEXT NOT NULL DEFAULT '',
			last_seen TIMESTAMP NOT NULL,
			revision INTEGER NOT NULL DEFAULT 0,
			updated_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS inbound_profiles (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			protocol TEXT NOT NULL,
			listen_host TEXT NOT NULL,
			listen_port INTEGER NOT NULL,
			transport TEXT NOT NULL,
			server_name TEXT NOT NULL,
			public_host TEXT NOT NULL,
			path TEXT NOT NULL,
			password TEXT NOT NULL,
			reality_public_key TEXT NOT NULL,
			reality_private_key TEXT NOT NULL DEFAULT '',
			reality_handshake_server TEXT NOT NULL DEFAULT '',
			reality_handshake_port INTEGER NOT NULL DEFAULT 443,
			reality_short_id TEXT NOT NULL,
			tls_mode TEXT NOT NULL,
			tls_cert_path TEXT NOT NULL DEFAULT '',
			tls_key_path TEXT NOT NULL DEFAULT '',
			shadowsocks_method TEXT NOT NULL DEFAULT '',
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL,
			modified_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS node_inbound_bindings (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			inbound_profile_id TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			UNIQUE(node_id, inbound_profile_id)
		)`,
		`CREATE TABLE IF NOT EXISTS topology_links (
			id TEXT PRIMARY KEY,
			source_node_id TEXT NOT NULL,
			target_node_id TEXT NOT NULL,
			role TEXT NOT NULL,
			transport TEXT NOT NULL,
			listen_port INTEGER NOT NULL,
			endpoint_host TEXT NOT NULL,
			endpoint_port INTEGER NOT NULL,
			allowed_cidrs TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS routing_policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT NOT NULL,
			mode TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS config_revisions (
			id TEXT PRIMARY KEY,
			node_id TEXT NOT NULL,
			revision INTEGER NOT NULL,
			config_json TEXT NOT NULL,
			config_hash TEXT NOT NULL,
			applied BOOLEAN NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL,
			UNIQUE(node_id, revision)
		)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id TEXT PRIMARY KEY,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			target_type TEXT NOT NULL,
			target_id TEXT NOT NULL,
			details TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`,
	}

	for _, stmt := range schema {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate schema: %w", err)
		}
	}
	if err := s.ensureColumn(ctx, "nodes", "address", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "nodes", "last_seen_ip", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "users", "telegram", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "users", "note", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	for _, column := range []struct {
		name string
		ddl  string
	}{
		{"reality_private_key", "TEXT NOT NULL DEFAULT ''"},
		{"reality_handshake_server", "TEXT NOT NULL DEFAULT ''"},
		{"reality_handshake_port", "INTEGER NOT NULL DEFAULT 443"},
		{"tls_cert_path", "TEXT NOT NULL DEFAULT ''"},
		{"tls_key_path", "TEXT NOT NULL DEFAULT ''"},
		{"shadowsocks_method", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := s.ensureColumn(ctx, "inbound_profiles", column.name, column.ddl); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureColumn(ctx context.Context, table, column, ddl string) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return fmt.Errorf("pragma table info %s: %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
			return fmt.Errorf("scan table info %s: %w", table, err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate table info %s: %w", table, err)
	}
	if _, err := s.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+ddl); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	return nil
}

func (s *Store) seedDefaults(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&count); err != nil {
		return fmt.Errorf("count admins: %w", err)
	}
	if count == 0 {
		id, err := secret.ID("admin")
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO admins(id, name, created_at) VALUES(?, ?, ?)`, id, "bootstrap-admin", time.Now().UTC()); err != nil {
			return fmt.Errorf("seed admin: %w", err)
		}
	}
	return nil
}

func (s *Store) Audit(ctx context.Context, actor, action, targetType, targetID, details string) error {
	id, err := secret.ID("audit")
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO audit_events(id, actor, action, target_type, target_id, details, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		id,
		actor,
		action,
		targetType,
		targetID,
		details,
		time.Now().UTC(),
	)
	return err
}

func (s *Store) CreateNode(ctx context.Context, params CreateNodeParams) (model.Node, error) {
	nodeID, err := secret.ID("node")
	if err != nil {
		return model.Node{}, err
	}
	token, err := secret.Hex(24)
	if err != nil {
		return model.Node{}, err
	}
	tokenID, err := secret.ID("enroll")
	if err != nil {
		return model.Node{}, err
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO nodes(id, name, address, is_local, role, status, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		nodeID,
		params.Name,
		params.Address,
		params.IsLocal,
		params.Role,
		"pending",
		now,
		now,
	)
	if err != nil {
		return model.Node{}, fmt.Errorf("insert node: %w", err)
	}
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO node_enroll_tokens(id, node_id, token, created_at) VALUES(?, ?, ?, ?)`,
		tokenID,
		nodeID,
		token,
		now,
	)
	if err != nil {
		return model.Node{}, fmt.Errorf("insert enroll token: %w", err)
	}

	node, err := s.GetNode(ctx, nodeID)
	if err != nil {
		return model.Node{}, err
	}
	node.EnrollToken = token
	_ = s.Audit(ctx, "admin", "create", "node", nodeID, params.Name)
	return node, nil
}

func (s *Store) GetNode(ctx context.Context, nodeID string) (model.Node, error) {
	row := s.db.QueryRowContext(ctx, `SELECT n.id, n.name, n.address, n.is_local, n.role, n.status, n.last_heartbeat, n.last_seen_ip, n.active_revision, n.last_apply_error, n.cert_serial, n.created_at, n.updated_at, COALESCE((SELECT token FROM node_enroll_tokens t WHERE t.node_id = n.id ORDER BY created_at DESC LIMIT 1), '') FROM nodes n WHERE n.id = ?`, nodeID)
	node, err := scanNode(row)
	if err != nil {
		return model.Node{}, err
	}
	return node, nil
}

func (s *Store) ListNodes(ctx context.Context) ([]model.Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT n.id, n.name, n.address, n.is_local, n.role, n.status, n.last_heartbeat, n.last_seen_ip, n.active_revision, n.last_apply_error, n.cert_serial, n.created_at, n.updated_at, COALESCE((SELECT token FROM node_enroll_tokens t WHERE t.node_id = n.id ORDER BY created_at DESC LIMIT 1), '') FROM nodes n ORDER BY n.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()

	var out []model.Node
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, node)
	}
	return out, rows.Err()
}

func (s *Store) EnrollNodeByToken(ctx context.Context, token string) (model.Node, error) {
	var nodeID string
	var usedAt sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT node_id, used_at FROM node_enroll_tokens WHERE token = ?`, token).Scan(&nodeID, &usedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Node{}, ErrNotFound
		}
		return model.Node{}, fmt.Errorf("find enroll token: %w", err)
	}
	if usedAt.Valid {
		return model.Node{}, fmt.Errorf("enroll token already used")
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE node_enroll_tokens SET used_at = ? WHERE token = ?`, time.Now().UTC(), token); err != nil {
		return model.Node{}, fmt.Errorf("mark enroll token used: %w", err)
	}
	node, err := s.GetNode(ctx, nodeID)
	if err != nil {
		return model.Node{}, err
	}
	return node, nil
}

// IssueEnrollToken generates a new unused enroll token for the given node.
func (s *Store) IssueEnrollToken(ctx context.Context, nodeID string) (string, error) {
	token, err := secret.Hex(24)
	if err != nil {
		return "", err
	}
	return s.IssueEnrollTokenValue(ctx, nodeID, token)
}

func (s *Store) IssueEnrollTokenValue(ctx context.Context, nodeID, token string) (string, error) {
	if token == "" {
		generated, err := secret.Hex(24)
		if err != nil {
			return "", err
		}
		token = generated
	}

	var existingNodeID string
	err := s.db.QueryRowContext(ctx, `SELECT node_id FROM node_enroll_tokens WHERE token = ?`, token).Scan(&existingNodeID)
	switch {
	case err == nil:
		if existingNodeID != nodeID {
			return "", fmt.Errorf("enroll token already belongs to another node")
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE node_enroll_tokens SET used_at = NULL WHERE token = ?`, token); err != nil {
			return "", fmt.Errorf("reset enroll token: %w", err)
		}
		return token, nil
	case errors.Is(err, sql.ErrNoRows):
	default:
		return "", fmt.Errorf("find enroll token: %w", err)
	}

	tokenID, err := secret.ID("enroll")
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO node_enroll_tokens(id, node_id, token, created_at) VALUES(?, ?, ?, ?)`,
		tokenID, nodeID, token, time.Now().UTC(),
	)
	if err != nil {
		return "", fmt.Errorf("insert enroll token: %w", err)
	}
	return token, nil
}

func (s *Store) EnsureLocalNode(ctx context.Context, token string) (model.Node, error) {
	nodes, err := s.ListNodes(ctx)
	if err != nil {
		return model.Node{}, err
	}
	for _, node := range nodes {
		if !node.IsLocal {
			continue
		}
		if token != "" {
			if _, err := s.IssueEnrollTokenValue(ctx, node.ID, token); err != nil {
				return model.Node{}, err
			}
			node.EnrollToken = token
		}
		return node, nil
	}

	node, err := s.CreateNode(ctx, CreateNodeParams{
		Name:    "local-panel",
		Address: "127.0.0.1",
		Role:    "edge",
		IsLocal: true,
	})
	if err != nil {
		return model.Node{}, err
	}
	if token != "" {
		if _, err := s.IssueEnrollTokenValue(ctx, node.ID, token); err != nil {
			return model.Node{}, err
		}
		node.EnrollToken = token
	}
	return node, nil
}

func (s *Store) SaveNodeCertificate(ctx context.Context, nodeID, serial, certPEM string, notAfter time.Time) error {
	id, err := secret.ID("cert")
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO node_certificates(id, node_id, serial, pem, not_after, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		id,
		nodeID,
		serial,
		certPEM,
		notAfter.UTC(),
		time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert node certificate: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE nodes SET cert_serial = ?, status = ?, updated_at = ? WHERE id = ?`, serial, "enrolled", time.Now().UTC(), nodeID)
	if err != nil {
		return fmt.Errorf("update node cert serial: %w", err)
	}
	_ = s.Audit(ctx, "panel", "issue_cert", "node", nodeID, serial)
	return nil
}

func (s *Store) UpdateNodeStatus(ctx context.Context, nodeID, status, lastError, lastSeenIP string, revision int) error {
	now := time.Now().UTC()
	statusID, err := secret.ID("status")
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO node_status(id, node_id, reported_status, last_error, last_seen, revision, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(node_id) DO UPDATE SET reported_status = excluded.reported_status, last_error = excluded.last_error, last_seen = excluded.last_seen, revision = excluded.revision, updated_at = excluded.updated_at`,
		statusID,
		nodeID,
		status,
		lastError,
		now,
		revision,
		now,
	)
	if err != nil {
		return fmt.Errorf("upsert node status: %w", err)
	}
	_, err = s.db.ExecContext(
		ctx,
		`UPDATE nodes SET status = ?, last_heartbeat = ?, last_seen_ip = ?, active_revision = ?, last_apply_error = ?, updated_at = ? WHERE id = ?`,
		status,
		now,
		lastSeenIP,
		revision,
		lastError,
		now,
		nodeID,
	)
	return err
}

func (s *Store) MarkConfigApplied(ctx context.Context, nodeID string, revision int, success bool, lastError string) error {
	applied := 0
	status := "error"
	if success {
		applied = 1
		status = "healthy"
	}
	_, err := s.db.ExecContext(ctx, `UPDATE config_revisions SET applied = ? WHERE node_id = ? AND revision = ?`, applied, nodeID, revision)
	if err != nil {
		return fmt.Errorf("update config applied: %w", err)
	}
	node, err := s.GetNode(ctx, nodeID)
	if err != nil {
		return err
	}
	return s.UpdateNodeStatus(ctx, nodeID, status, lastError, node.LastSeenIP, revision)
}

func (s *Store) EnsureConfigRevision(ctx context.Context, nodeID, configJSON string) (model.ConfigRevision, error) {
	hashBytes := sha256.Sum256([]byte(configJSON))
	hash := hex.EncodeToString(hashBytes[:])

	var existing model.ConfigRevision
	row := s.db.QueryRowContext(ctx, `SELECT id, node_id, revision, config_json, config_hash, applied, created_at FROM config_revisions WHERE node_id = ? ORDER BY revision DESC LIMIT 1`, nodeID)
	switch err := row.Scan(&existing.ID, &existing.NodeID, &existing.Revision, &existing.ConfigJSON, &existing.ConfigHash, &existing.Applied, &existing.CreatedAt); {
	case err == nil:
		if existing.ConfigHash == hash {
			return existing, nil
		}
	case errors.Is(err, sql.ErrNoRows):
	default:
		return model.ConfigRevision{}, fmt.Errorf("query latest config revision: %w", err)
	}

	id, err := secret.ID("rev")
	if err != nil {
		return model.ConfigRevision{}, err
	}
	revision := existing.Revision + 1
	createdAt := time.Now().UTC()
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO config_revisions(id, node_id, revision, config_json, config_hash, applied, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		id,
		nodeID,
		revision,
		configJSON,
		hash,
		false,
		createdAt,
	)
	if err != nil {
		return model.ConfigRevision{}, fmt.Errorf("insert config revision: %w", err)
	}
	return model.ConfigRevision{
		ID:         id,
		NodeID:     nodeID,
		Revision:   revision,
		ConfigJSON: configJSON,
		ConfigHash: hash,
		Applied:    false,
		CreatedAt:  createdAt,
	}, nil
}

func (s *Store) ListConfigRevisions(ctx context.Context) ([]model.ConfigRevision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, node_id, revision, config_json, config_hash, applied, created_at FROM config_revisions ORDER BY created_at DESC LIMIT 25`)
	if err != nil {
		return nil, fmt.Errorf("list config revisions: %w", err)
	}
	defer rows.Close()

	var out []model.ConfigRevision
	for rows.Next() {
		var rev model.ConfigRevision
		if err := rows.Scan(&rev.ID, &rev.NodeID, &rev.Revision, &rev.ConfigJSON, &rev.ConfigHash, &rev.Applied, &rev.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan config revision: %w", err)
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, params CreateUserParams) (model.User, error) {
	id, err := secret.ID("user")
	if err != nil {
		return model.User{}, err
	}
	accessKey, err := secret.UUIDLike()
	if err != nil {
		return model.User{}, err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO users(id, name, email, telegram, note, access_key, created_at, modified_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		id,
		params.Name,
		params.Email,
		params.Telegram,
		params.Note,
		accessKey,
		now,
		now,
	)
	if err != nil {
		return model.User{}, fmt.Errorf("insert user: %w", err)
	}
	_ = s.Audit(ctx, "admin", "create", "user", id, params.Email)
	return model.User{ID: id, Name: params.Name, Email: params.Email, Telegram: params.Telegram, Note: params.Note, AccessKey: accessKey, CreatedAt: now, ModifiedAt: now}, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, email, telegram, note, access_key, created_at, modified_at FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []model.User
	for rows.Next() {
		var user model.User
		if err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.Telegram, &user.Note, &user.AccessKey, &user.CreatedAt, &user.ModifiedAt); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, user)
	}
	return out, rows.Err()
}

func (s *Store) CreateSubscription(ctx context.Context, params CreateSubscriptionParams) (model.Subscription, error) {
	id, err := secret.ID("sub")
	if err != nil {
		return model.Subscription{}, err
	}
	tokenID, err := secret.ID("stok")
	if err != nil {
		return model.Subscription{}, err
	}
	token, err := secret.Hex(24)
	if err != nil {
		return model.Subscription{}, err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO subscriptions(id, user_id, name, status, expires_at, created_at, modified_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		id,
		params.UserID,
		params.Name,
		"active",
		params.ExpiresAt.UTC(),
		now,
		now,
	)
	if err != nil {
		return model.Subscription{}, fmt.Errorf("insert subscription: %w", err)
	}
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO subscription_tokens(id, subscription_id, token, created_at) VALUES(?, ?, ?, ?)`,
		tokenID,
		id,
		token,
		now,
	)
	if err != nil {
		return model.Subscription{}, fmt.Errorf("insert subscription token: %w", err)
	}
	_ = s.Audit(ctx, "admin", "create", "subscription", id, params.Name)
	return model.Subscription{ID: id, UserID: params.UserID, Name: params.Name, Status: "active", ExpiresAt: params.ExpiresAt.UTC(), Token: token, CreatedAt: now, ModifiedAt: now}, nil
}

func (s *Store) ListSubscriptions(ctx context.Context) ([]model.Subscription, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id, s.user_id, s.name, s.status, s.expires_at, t.token, s.created_at, s.modified_at FROM subscriptions s JOIN subscription_tokens t ON t.subscription_id = s.id ORDER BY s.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}
	defer rows.Close()

	var out []model.Subscription
	for rows.Next() {
		var sub model.Subscription
		if err := rows.Scan(&sub.ID, &sub.UserID, &sub.Name, &sub.Status, &sub.ExpiresAt, &sub.Token, &sub.CreatedAt, &sub.ModifiedAt); err != nil {
			return nil, fmt.Errorf("scan subscription: %w", err)
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

func (s *Store) CreateInboundProfile(ctx context.Context, params CreateInboundProfileParams) (model.InboundProfile, error) {
	id, err := secret.ID("in")
	if err != nil {
		return model.InboundProfile{}, err
	}
	metadata, err := json.Marshal(params.Metadata)
	if err != nil {
		return model.InboundProfile{}, fmt.Errorf("marshal metadata: %w", err)
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO inbound_profiles(id, name, protocol, listen_host, listen_port, transport, server_name, public_host, path, password, reality_public_key, reality_private_key, reality_handshake_server, reality_handshake_port, reality_short_id, tls_mode, tls_cert_path, tls_key_path, shadowsocks_method, metadata_json, created_at, modified_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id,
		params.Name,
		params.Protocol,
		params.ListenHost,
		params.ListenPort,
		params.Transport,
		params.ServerName,
		params.PublicHost,
		params.Path,
		params.Password,
		params.RealityPubKey,
		params.RealityPrivateKey,
		params.RealityHandshakeServer,
		params.RealityHandshakePort,
		params.RealityShort,
		params.TLSMode,
		params.TLSCertPath,
		params.TLSKeyPath,
		params.ShadowsocksMethod,
		string(metadata),
		now,
		now,
	)
	if err != nil {
		return model.InboundProfile{}, fmt.Errorf("insert inbound profile: %w", err)
	}
	_ = s.Audit(ctx, "admin", "create", "inbound_profile", id, params.Name)
	return model.InboundProfile{
		ID:                     id,
		Name:                   params.Name,
		Protocol:               params.Protocol,
		ListenHost:             params.ListenHost,
		ListenPort:             params.ListenPort,
		Transport:              params.Transport,
		ServerName:             params.ServerName,
		PublicHost:             params.PublicHost,
		Path:                   params.Path,
		Password:               params.Password,
		RealityPubKey:          params.RealityPubKey,
		RealityPrivateKey:     params.RealityPrivateKey,
		RealityHandshakeServer: params.RealityHandshakeServer,
		RealityHandshakePort:   params.RealityHandshakePort,
		RealityShort:           params.RealityShort,
		TLSMode:                params.TLSMode,
		TLSCertPath:            params.TLSCertPath,
		TLSKeyPath:             params.TLSKeyPath,
		ShadowsocksMethod:      params.ShadowsocksMethod,
		Metadata:               params.Metadata,
		CreatedAt:              now,
		ModifiedAt:             now,
	}, nil
}

func (s *Store) ListInboundProfiles(ctx context.Context) ([]model.InboundProfile, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, protocol, listen_host, listen_port, transport, server_name, public_host, path, password, reality_public_key, reality_private_key, reality_handshake_server, reality_handshake_port, reality_short_id, tls_mode, tls_cert_path, tls_key_path, shadowsocks_method, metadata_json, created_at, modified_at FROM inbound_profiles ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list inbound profiles: %w", err)
	}
	defer rows.Close()

	var out []model.InboundProfile
	for rows.Next() {
		var item model.InboundProfile
		var metadataJSON string
		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&item.Protocol,
			&item.ListenHost,
			&item.ListenPort,
			&item.Transport,
			&item.ServerName,
			&item.PublicHost,
			&item.Path,
			&item.Password,
			&item.RealityPubKey,
			&item.RealityPrivateKey,
			&item.RealityHandshakeServer,
			&item.RealityHandshakePort,
			&item.RealityShort,
			&item.TLSMode,
			&item.TLSCertPath,
			&item.TLSKeyPath,
			&item.ShadowsocksMethod,
			&metadataJSON,
			&item.CreatedAt,
			&item.ModifiedAt,
		); err != nil {
			return nil, fmt.Errorf("scan inbound profile: %w", err)
		}
		if err := json.Unmarshal([]byte(metadataJSON), &item.Metadata); err != nil {
			item.Metadata = map[string]string{}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateNodeInboundBinding(ctx context.Context, nodeID, inboundProfileID string) (model.NodeInboundBinding, error) {
	id, err := secret.ID("bind")
	if err != nil {
		return model.NodeInboundBinding{}, err
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO node_inbound_bindings(id, node_id, inbound_profile_id, created_at) VALUES(?, ?, ?, ?)`, id, nodeID, inboundProfileID, now)
	if err != nil {
		return model.NodeInboundBinding{}, fmt.Errorf("insert binding: %w", err)
	}
	if affected, err := res.RowsAffected(); err == nil && affected == 0 {
		return model.NodeInboundBinding{}, fmt.Errorf("binding already exists")
	}
	_ = s.Audit(ctx, "admin", "bind", "node_inbound", nodeID, inboundProfileID)
	return model.NodeInboundBinding{ID: id, NodeID: nodeID, InboundProfileID: inboundProfileID, CreatedAt: now}, nil
}

func (s *Store) ListBindings(ctx context.Context) ([]model.NodeInboundBinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, node_id, inbound_profile_id, created_at FROM node_inbound_bindings ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	defer rows.Close()

	var out []model.NodeInboundBinding
	for rows.Next() {
		var binding model.NodeInboundBinding
		if err := rows.Scan(&binding.ID, &binding.NodeID, &binding.InboundProfileID, &binding.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan binding: %w", err)
		}
		out = append(out, binding)
	}
	return out, rows.Err()
}

func (s *Store) CreateTopologyLink(ctx context.Context, params CreateTopologyLinkParams) (model.TopologyLink, error) {
	id, err := secret.ID("link")
	if err != nil {
		return model.TopologyLink{}, err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO topology_links(id, source_node_id, target_node_id, role, transport, listen_port, endpoint_host, endpoint_port, allowed_cidrs, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id,
		params.SourceNodeID,
		params.TargetNodeID,
		params.Role,
		params.Transport,
		params.ListenPort,
		params.EndpointHost,
		params.EndpointPort,
		params.AllowedCIDRs,
		now,
	)
	if err != nil {
		return model.TopologyLink{}, fmt.Errorf("insert topology link: %w", err)
	}
	_ = s.Audit(ctx, "admin", "create", "topology_link", id, params.Role)
	return model.TopologyLink{
		ID:           id,
		SourceNodeID: params.SourceNodeID,
		TargetNodeID: params.TargetNodeID,
		Role:         params.Role,
		Transport:    params.Transport,
		ListenPort:   params.ListenPort,
		EndpointHost: params.EndpointHost,
		EndpointPort: params.EndpointPort,
		AllowedCIDRs: params.AllowedCIDRs,
		CreatedAt:    now,
	}, nil
}

func (s *Store) ListTopologyLinks(ctx context.Context) ([]model.TopologyLink, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, source_node_id, target_node_id, role, transport, listen_port, endpoint_host, endpoint_port, allowed_cidrs, created_at FROM topology_links ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list topology links: %w", err)
	}
	defer rows.Close()

	var out []model.TopologyLink
	for rows.Next() {
		var link model.TopologyLink
		if err := rows.Scan(&link.ID, &link.SourceNodeID, &link.TargetNodeID, &link.Role, &link.Transport, &link.ListenPort, &link.EndpointHost, &link.EndpointPort, &link.AllowedCIDRs, &link.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan topology link: %w", err)
		}
		out = append(out, link)
	}
	return out, rows.Err()
}

func (s *Store) Dashboard(ctx context.Context) (model.Dashboard, error) {
	nodes, err := s.ListNodes(ctx)
	if err != nil {
		return model.Dashboard{}, err
	}
	users, err := s.ListUsers(ctx)
	if err != nil {
		return model.Dashboard{}, err
	}
	subs, err := s.ListSubscriptions(ctx)
	if err != nil {
		return model.Dashboard{}, err
	}
	inbounds, err := s.ListInboundProfiles(ctx)
	if err != nil {
		return model.Dashboard{}, err
	}
	bindings, err := s.ListBindings(ctx)
	if err != nil {
		return model.Dashboard{}, err
	}
	links, err := s.ListTopologyLinks(ctx)
	if err != nil {
		return model.Dashboard{}, err
	}
	revisions, err := s.ListConfigRevisions(ctx)
	if err != nil {
		return model.Dashboard{}, err
	}
	return model.Dashboard{
		Nodes:         nodes,
		Users:         users,
		Subscriptions: subs,
		Inbounds:      inbounds,
		Bindings:      bindings,
		TopologyLinks: links,
		Revisions:     revisions,
	}, nil
}

func (s *Store) PortalDataByToken(ctx context.Context, token string) (PortalData, error) {
	var portal PortalData
	row := s.db.QueryRowContext(
		ctx,
		`SELECT u.id, u.name, u.email, u.telegram, u.note, u.access_key, u.created_at, u.modified_at,
		        s.id, s.user_id, s.name, s.status, s.expires_at, t.token, s.created_at, s.modified_at
		   FROM subscription_tokens t
		   JOIN subscriptions s ON s.id = t.subscription_id
		   JOIN users u ON u.id = s.user_id
		  WHERE t.token = ?`,
		token,
	)
	if err := row.Scan(
		&portal.User.ID,
		&portal.User.Name,
		&portal.User.Email,
		&portal.User.Telegram,
		&portal.User.Note,
		&portal.User.AccessKey,
		&portal.User.CreatedAt,
		&portal.User.ModifiedAt,
		&portal.Subscription.ID,
		&portal.Subscription.UserID,
		&portal.Subscription.Name,
		&portal.Subscription.Status,
		&portal.Subscription.ExpiresAt,
		&portal.Subscription.Token,
		&portal.Subscription.CreatedAt,
		&portal.Subscription.ModifiedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PortalData{}, ErrNotFound
		}
		return PortalData{}, fmt.Errorf("load portal data: %w", err)
	}
	if portal.Subscription.Status != "active" || !portal.Subscription.ExpiresAt.After(time.Now().UTC()) {
		return PortalData{}, ErrNotFound
	}

	nodes, err := s.ListNodes(ctx)
	if err != nil {
		return PortalData{}, err
	}
	inbounds, err := s.ListInboundProfiles(ctx)
	if err != nil {
		return PortalData{}, err
	}
	bindings, err := s.ListBindings(ctx)
	if err != nil {
		return PortalData{}, err
	}
	portal.Nodes = nodes
	portal.Inbounds = inbounds
	portal.Bindings = bindings
	return portal, nil
}

func (s *Store) NodeBundle(ctx context.Context, nodeID string) (model.Node, []model.InboundProfile, []model.TopologyLink, []model.Subscription, []model.User, error) {
	node, err := s.GetNode(ctx, nodeID)
	if err != nil {
		return model.Node{}, nil, nil, nil, nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT p.id, p.name, p.protocol, p.listen_host, p.listen_port, p.transport, p.server_name, p.public_host, p.path, p.password, p.reality_public_key, p.reality_private_key, p.reality_handshake_server, p.reality_handshake_port, p.reality_short_id, p.tls_mode, p.tls_cert_path, p.tls_key_path, p.shadowsocks_method, p.metadata_json, p.created_at, p.modified_at
		   FROM inbound_profiles p
		   JOIN node_inbound_bindings b ON b.inbound_profile_id = p.id
		  WHERE b.node_id = ?
		  ORDER BY p.created_at DESC`,
		nodeID,
	)
	if err != nil {
		return model.Node{}, nil, nil, nil, nil, fmt.Errorf("query node inbound profiles: %w", err)
	}
	defer rows.Close()
	var inbounds []model.InboundProfile
	for rows.Next() {
		var item model.InboundProfile
		var metadataJSON string
		if err := rows.Scan(&item.ID, &item.Name, &item.Protocol, &item.ListenHost, &item.ListenPort, &item.Transport, &item.ServerName, &item.PublicHost, &item.Path, &item.Password, &item.RealityPubKey, &item.RealityPrivateKey, &item.RealityHandshakeServer, &item.RealityHandshakePort, &item.RealityShort, &item.TLSMode, &item.TLSCertPath, &item.TLSKeyPath, &item.ShadowsocksMethod, &metadataJSON, &item.CreatedAt, &item.ModifiedAt); err != nil {
			return model.Node{}, nil, nil, nil, nil, fmt.Errorf("scan node inbound profile: %w", err)
		}
		if err := json.Unmarshal([]byte(metadataJSON), &item.Metadata); err != nil {
			item.Metadata = map[string]string{}
		}
		inbounds = append(inbounds, item)
	}
	if err := rows.Err(); err != nil {
		return model.Node{}, nil, nil, nil, nil, err
	}

	links, err := s.ListTopologyLinks(ctx)
	if err != nil {
		return model.Node{}, nil, nil, nil, nil, err
	}
	var filteredLinks []model.TopologyLink
	for _, link := range links {
		if link.SourceNodeID == nodeID || link.TargetNodeID == nodeID {
			filteredLinks = append(filteredLinks, link)
		}
	}

	subscriptions, err := s.ListSubscriptions(ctx)
	if err != nil {
		return model.Node{}, nil, nil, nil, nil, err
	}
	var activeSubs []model.Subscription
	for _, sub := range subscriptions {
		if sub.Status == "active" && sub.ExpiresAt.After(time.Now().UTC()) {
			activeSubs = append(activeSubs, sub)
		}
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		return model.Node{}, nil, nil, nil, nil, err
	}

	return node, inbounds, filteredLinks, activeSubs, users, nil
}

func scanNode(scanner interface{ Scan(dest ...any) error }) (model.Node, error) {
	var node model.Node
	var heartbeat sql.NullTime
	var enrollToken sql.NullString
	if err := scanner.Scan(
		&node.ID,
		&node.Name,
		&node.Address,
		&node.IsLocal,
		&node.Role,
		&node.Status,
		&heartbeat,
		&node.LastSeenIP,
		&node.ActiveRevision,
		&node.LastApplyError,
		&node.CertSerial,
		&node.CreatedAt,
		&node.UpdatedAt,
		&enrollToken,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Node{}, ErrNotFound
		}
		return model.Node{}, fmt.Errorf("scan node: %w", err)
	}
	if heartbeat.Valid {
		node.LastHeartbeat = heartbeat.Time
	}
	if enrollToken.Valid {
		node.EnrollToken = enrollToken.String
	}
	return node, nil
}
