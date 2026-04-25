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
	"strings"
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
	UserID     string
	Name       string
	ExpiresAt  time.Time
	BindingIDs []string
	PlanIDs    []string
}

type CreateSubscriptionPlanParams struct {
	Name       string
	BindingIDs []string
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
	RealityPrivateKey      string
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
		`CREATE TABLE IF NOT EXISTS subscription_binding_items (
			id TEXT PRIMARY KEY,
			subscription_id TEXT NOT NULL,
			node_inbound_binding_id TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			UNIQUE(subscription_id, node_inbound_binding_id)
		)`,
		`CREATE TABLE IF NOT EXISTS subscription_plans (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			modified_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS subscription_plan_binding_items (
			id TEXT PRIMARY KEY,
			subscription_plan_id TEXT NOT NULL,
			node_inbound_binding_id TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			UNIQUE(subscription_plan_id, node_inbound_binding_id)
		)`,
		`CREATE TABLE IF NOT EXISTS user_subscription_plans (
			id TEXT PRIMARY KEY,
			subscription_id TEXT NOT NULL,
			subscription_plan_id TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			UNIQUE(subscription_id, subscription_plan_id)
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
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			u.id,
			u.name,
			u.email,
			u.telegram,
			u.note,
			u.access_key,
			COALESCE(s.id, ''),
			COALESCE(s.name, ''),
			COALESCE(s.status, ''),
			s.expires_at,
			COALESCE(t.token, ''),
			u.created_at,
			u.modified_at
		FROM users u
		LEFT JOIN subscriptions s ON s.id = (
			SELECT s2.id
			FROM subscriptions s2
			WHERE s2.user_id = u.id
			ORDER BY
				CASE WHEN s2.status = 'active' THEN 0 ELSE 1 END,
				s2.expires_at DESC,
				s2.created_at DESC
			LIMIT 1
		)
		LEFT JOIN subscription_tokens t ON t.subscription_id = s.id
		ORDER BY u.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []model.User
	for rows.Next() {
		var user model.User
		var expiresAt sql.NullTime
		if err := rows.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.Telegram,
			&user.Note,
			&user.AccessKey,
			&user.CurrentSubscriptionID,
			&user.CurrentSubscriptionName,
			&user.CurrentSubscriptionStatus,
			&expiresAt,
			&user.CurrentSubscriptionToken,
			&user.CreatedAt,
			&user.ModifiedAt,
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if expiresAt.Valid {
			user.CurrentSubscriptionExpiresAt = expiresAt.Time
		}
		out = append(out, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].CurrentSubscriptionID == "" {
			continue
		}
		sub, err := s.currentSubscriptionByUser(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].CurrentSubscriptionName = sub.Name
		out[i].CurrentSubscriptionPlanIDs = sub.PlanIDs
		out[i].CurrentSubscriptionPlanNames = sub.PlanNames
	}
	return out, nil
}

func (s *Store) UpdateUser(ctx context.Context, userID string, params CreateUserParams) (model.User, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(
		ctx,
		`UPDATE users SET name = ?, email = ?, telegram = ?, note = ?, modified_at = ? WHERE id = ?`,
		params.Name,
		params.Email,
		params.Telegram,
		params.Note,
		now,
		userID,
	)
	if err != nil {
		return model.User{}, fmt.Errorf("update user: %w", err)
	}
	if affected, err := res.RowsAffected(); err == nil && affected == 0 {
		return model.User{}, ErrNotFound
	}
	_ = s.Audit(ctx, "admin", "update", "user", userID, params.Email)

	users, err := s.ListUsers(ctx)
	if err != nil {
		return model.User{}, err
	}
	for _, user := range users {
		if user.ID == userID {
			return user, nil
		}
	}
	return model.User{}, ErrNotFound
}

func (s *Store) currentSubscriptionByUser(ctx context.Context, userID string) (model.Subscription, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT s.id, s.user_id, s.name, s.status, s.expires_at, COALESCE(t.token, ''), s.created_at, s.modified_at
		FROM subscriptions s
		LEFT JOIN subscription_tokens t ON t.subscription_id = s.id
		WHERE s.user_id = ?
		ORDER BY
			CASE WHEN s.status = 'active' THEN 0 ELSE 1 END,
			s.expires_at DESC,
			s.created_at DESC
		LIMIT 1`,
		userID,
	)

	var sub model.Subscription
	if err := row.Scan(&sub.ID, &sub.UserID, &sub.Name, &sub.Status, &sub.ExpiresAt, &sub.Token, &sub.CreatedAt, &sub.ModifiedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Subscription{}, ErrNotFound
		}
		return model.Subscription{}, fmt.Errorf("load current subscription: %w", err)
	}
	if err := s.hydrateSubscriptionAccess(ctx, &sub); err != nil {
		return model.Subscription{}, err
	}
	return sub, nil
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (s *Store) replaceSubscriptionBindingItems(ctx context.Context, subscriptionID string, bindingIDs []string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM subscription_binding_items WHERE subscription_id = ?`, subscriptionID); err != nil {
		return fmt.Errorf("clear subscription bindings: %w", err)
	}

	now := time.Now().UTC()
	for _, bindingID := range dedupeStrings(bindingIDs) {
		id, err := secret.ID("sbind")
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(
			ctx,
			`INSERT INTO subscription_binding_items(id, subscription_id, node_inbound_binding_id, created_at) VALUES(?, ?, ?, ?)`,
			id,
			subscriptionID,
			bindingID,
			now,
		); err != nil {
			return fmt.Errorf("insert subscription binding item: %w", err)
		}
	}
	return nil
}

func (s *Store) listSubscriptionBindingItems(ctx context.Context, subscriptionID string) ([]model.SubscriptionBindingItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			sbi.id,
			sbi.subscription_id,
			sbi.node_inbound_binding_id,
			nb.node_id,
			n.name,
			n.address,
			nb.inbound_profile_id,
			ip.name,
			ip.protocol,
			ip.listen_port,
			ip.transport,
			ip.tls_mode,
			COALESCE(NULLIF(ip.public_host, ''), NULLIF(ip.server_name, ''), n.address, n.name)
		FROM subscription_binding_items sbi
		JOIN node_inbound_bindings nb ON nb.id = sbi.node_inbound_binding_id
		JOIN nodes n ON n.id = nb.node_id
		JOIN inbound_profiles ip ON ip.id = nb.inbound_profile_id
		WHERE sbi.subscription_id = ?
		ORDER BY n.name, ip.name`,
		subscriptionID,
	)
	if err != nil {
		return nil, fmt.Errorf("list subscription binding items: %w", err)
	}
	defer rows.Close()

	var out []model.SubscriptionBindingItem
	for rows.Next() {
		var item model.SubscriptionBindingItem
		if err := rows.Scan(
			&item.ID,
			&item.SubscriptionID,
			&item.NodeInboundBindingID,
			&item.NodeID,
			&item.NodeName,
			&item.NodeAddress,
			&item.InboundProfileID,
			&item.InboundName,
			&item.Protocol,
			&item.ListenPort,
			&item.Transport,
			&item.TLSMode,
			&item.PublicHost,
		); err != nil {
			return nil, fmt.Errorf("scan subscription binding item: %w", err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) replaceUserSubscriptionPlans(ctx context.Context, subscriptionID string, planIDs []string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM user_subscription_plans WHERE subscription_id = ?`, subscriptionID); err != nil {
		return fmt.Errorf("clear user subscription plans: %w", err)
	}

	now := time.Now().UTC()
	for _, planID := range dedupeStrings(planIDs) {
		id, err := secret.ID("usplan")
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(
			ctx,
			`INSERT INTO user_subscription_plans(id, subscription_id, subscription_plan_id, created_at) VALUES(?, ?, ?, ?)`,
			id,
			subscriptionID,
			planID,
			now,
		); err != nil {
			return fmt.Errorf("insert user subscription plan: %w", err)
		}
	}
	return nil
}

func (s *Store) listSubscriptionPlanBindingItems(ctx context.Context, planID string) ([]model.SubscriptionBindingItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			spbi.id,
			spbi.subscription_plan_id,
			spbi.node_inbound_binding_id,
			nb.node_id,
			n.name,
			n.address,
			nb.inbound_profile_id,
			ip.name,
			ip.protocol,
			ip.listen_port,
			ip.transport,
			ip.tls_mode,
			COALESCE(NULLIF(ip.public_host, ''), NULLIF(ip.server_name, ''), n.address, n.name)
		FROM subscription_plan_binding_items spbi
		JOIN node_inbound_bindings nb ON nb.id = spbi.node_inbound_binding_id
		JOIN nodes n ON n.id = nb.node_id
		JOIN inbound_profiles ip ON ip.id = nb.inbound_profile_id
		WHERE spbi.subscription_plan_id = ?
		ORDER BY n.name, ip.name`,
		planID,
	)
	if err != nil {
		return nil, fmt.Errorf("list subscription plan binding items: %w", err)
	}
	defer rows.Close()

	var out []model.SubscriptionBindingItem
	for rows.Next() {
		var item model.SubscriptionBindingItem
		if err := rows.Scan(
			&item.ID,
			&item.SubscriptionPlanID,
			&item.NodeInboundBindingID,
			&item.NodeID,
			&item.NodeName,
			&item.NodeAddress,
			&item.InboundProfileID,
			&item.InboundName,
			&item.Protocol,
			&item.ListenPort,
			&item.Transport,
			&item.TLSMode,
			&item.PublicHost,
		); err != nil {
			return nil, fmt.Errorf("scan subscription plan binding item: %w", err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) listSubscriptionPlansForSubscription(ctx context.Context, subscriptionID string) ([]model.SubscriptionPlan, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.name, p.created_at, p.modified_at
		FROM user_subscription_plans usp
		JOIN subscription_plans p ON p.id = usp.subscription_plan_id
		WHERE usp.subscription_id = ?
		ORDER BY p.name`,
		subscriptionID,
	)
	if err != nil {
		return nil, fmt.Errorf("list user subscription plans: %w", err)
	}
	defer rows.Close()

	var out []model.SubscriptionPlan
	for rows.Next() {
		var plan model.SubscriptionPlan
		if err := rows.Scan(&plan.ID, &plan.Name, &plan.CreatedAt, &plan.ModifiedAt); err != nil {
			return nil, fmt.Errorf("scan user subscription plan: %w", err)
		}
		out = append(out, plan)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		items, err := s.listSubscriptionPlanBindingItems(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Bindings = items
		out[i].BindingCount = len(items)
	}
	return out, nil
}

func appendUniqueBindingItems(out []model.SubscriptionBindingItem, seen map[string]struct{}, items []model.SubscriptionBindingItem) []model.SubscriptionBindingItem {
	for _, item := range items {
		if item.NodeInboundBindingID == "" {
			continue
		}
		if _, ok := seen[item.NodeInboundBindingID]; ok {
			continue
		}
		seen[item.NodeInboundBindingID] = struct{}{}
		out = append(out, item)
	}
	return out
}

func (s *Store) hydrateSubscriptionAccess(ctx context.Context, sub *model.Subscription) error {
	directItems, err := s.listSubscriptionBindingItems(ctx, sub.ID)
	if err != nil {
		return err
	}
	plans, err := s.listSubscriptionPlansForSubscription(ctx, sub.ID)
	if err != nil {
		return err
	}

	seenBindings := make(map[string]struct{})
	bindings := appendUniqueBindingItems(nil, seenBindings, directItems)
	planNames := make([]string, 0, len(plans))
	planIDs := make([]string, 0, len(plans))
	for _, plan := range plans {
		planIDs = append(planIDs, plan.ID)
		planNames = append(planNames, plan.Name)
		bindings = appendUniqueBindingItems(bindings, seenBindings, plan.Bindings)
	}
	if len(planNames) > 0 {
		sub.Name = strings.Join(planNames, ", ")
	}
	sub.PlanIDs = planIDs
	sub.PlanNames = planNames
	sub.Plans = plans
	sub.Bindings = bindings
	sub.BindingCount = len(bindings)
	return nil
}

func (s *Store) subscriptionPlanNamesByID(ctx context.Context, planIDs []string) ([]string, error) {
	ids := dedupeStrings(planIDs)
	if len(ids) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(ids))
	for _, planID := range ids {
		var name string
		if err := s.db.QueryRowContext(ctx, `SELECT name FROM subscription_plans WHERE id = ?`, planID).Scan(&name); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, fmt.Errorf("load subscription plan name: %w", err)
		}
		names = append(names, name)
	}
	return names, nil
}

func (s *Store) UpdateUserSubscriptionPlans(ctx context.Context, userID string, planIDs []string, expiresAt time.Time) (model.Subscription, error) {
	names, err := s.subscriptionPlanNamesByID(ctx, planIDs)
	if err != nil {
		return model.Subscription{}, err
	}
	name := strings.Join(names, ", ")
	if name == "" {
		name = "Без наборов"
	}
	return s.CreateSubscription(ctx, CreateSubscriptionParams{
		UserID:    userID,
		Name:      name,
		ExpiresAt: expiresAt,
		PlanIDs:   planIDs,
	})
}

func (s *Store) CreateSubscription(ctx context.Context, params CreateSubscriptionParams) (model.Subscription, error) {
	now := time.Now().UTC()
	current, err := s.currentSubscriptionByUser(ctx, params.UserID)
	if err == nil {
		_, err = s.db.ExecContext(
			ctx,
			`UPDATE subscriptions SET name = ?, status = ?, expires_at = ?, modified_at = ? WHERE id = ?`,
			params.Name,
			"active",
			params.ExpiresAt.UTC(),
			now,
			current.ID,
		)
		if err != nil {
			return model.Subscription{}, fmt.Errorf("update subscription: %w", err)
		}
		if err := s.replaceSubscriptionBindingItems(ctx, current.ID, params.BindingIDs); err != nil {
			return model.Subscription{}, err
		}
		if err := s.replaceUserSubscriptionPlans(ctx, current.ID, params.PlanIDs); err != nil {
			return model.Subscription{}, err
		}
		updated, err := s.currentSubscriptionByUser(ctx, params.UserID)
		if err != nil {
			return model.Subscription{}, err
		}
		_ = s.Audit(ctx, "admin", "update", "subscription", updated.ID, params.Name)
		return updated, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return model.Subscription{}, err
	}

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
	if err := s.replaceSubscriptionBindingItems(ctx, id, params.BindingIDs); err != nil {
		return model.Subscription{}, err
	}
	if err := s.replaceUserSubscriptionPlans(ctx, id, params.PlanIDs); err != nil {
		return model.Subscription{}, err
	}
	created, err := s.currentSubscriptionByUser(ctx, params.UserID)
	if err != nil {
		return model.Subscription{}, err
	}
	_ = s.Audit(ctx, "admin", "create", "subscription", id, params.Name)
	return created, nil
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.hydrateSubscriptionAccess(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) replaceSubscriptionPlanBindingItems(ctx context.Context, planID string, bindingIDs []string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM subscription_plan_binding_items WHERE subscription_plan_id = ?`, planID); err != nil {
		return fmt.Errorf("clear subscription plan bindings: %w", err)
	}

	now := time.Now().UTC()
	for _, bindingID := range dedupeStrings(bindingIDs) {
		id, err := secret.ID("pbind")
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(
			ctx,
			`INSERT INTO subscription_plan_binding_items(id, subscription_plan_id, node_inbound_binding_id, created_at) VALUES(?, ?, ?, ?)`,
			id,
			planID,
			bindingID,
			now,
		); err != nil {
			return fmt.Errorf("insert subscription plan binding item: %w", err)
		}
	}
	return nil
}

func (s *Store) CreateSubscriptionPlan(ctx context.Context, params CreateSubscriptionPlanParams) (model.SubscriptionPlan, error) {
	id, err := secret.ID("plan")
	if err != nil {
		return model.SubscriptionPlan{}, err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO subscription_plans(id, name, created_at, modified_at) VALUES(?, ?, ?, ?)`,
		id,
		params.Name,
		now,
		now,
	)
	if err != nil {
		return model.SubscriptionPlan{}, fmt.Errorf("insert subscription plan: %w", err)
	}
	if err := s.replaceSubscriptionPlanBindingItems(ctx, id, params.BindingIDs); err != nil {
		return model.SubscriptionPlan{}, err
	}
	_ = s.Audit(ctx, "admin", "create", "subscription_plan", id, params.Name)
	return s.GetSubscriptionPlan(ctx, id)
}

func (s *Store) GetSubscriptionPlan(ctx context.Context, planID string) (model.SubscriptionPlan, error) {
	var plan model.SubscriptionPlan
	row := s.db.QueryRowContext(ctx, `SELECT id, name, created_at, modified_at FROM subscription_plans WHERE id = ?`, planID)
	if err := row.Scan(&plan.ID, &plan.Name, &plan.CreatedAt, &plan.ModifiedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.SubscriptionPlan{}, ErrNotFound
		}
		return model.SubscriptionPlan{}, fmt.Errorf("load subscription plan: %w", err)
	}
	items, err := s.listSubscriptionPlanBindingItems(ctx, plan.ID)
	if err != nil {
		return model.SubscriptionPlan{}, err
	}
	plan.Bindings = items
	plan.BindingCount = len(items)
	return plan, nil
}

func (s *Store) ListSubscriptionPlans(ctx context.Context) ([]model.SubscriptionPlan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at, modified_at FROM subscription_plans ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list subscription plans: %w", err)
	}
	defer rows.Close()

	var out []model.SubscriptionPlan
	for rows.Next() {
		var plan model.SubscriptionPlan
		if err := rows.Scan(&plan.ID, &plan.Name, &plan.CreatedAt, &plan.ModifiedAt); err != nil {
			return nil, fmt.Errorf("scan subscription plan: %w", err)
		}
		out = append(out, plan)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		items, err := s.listSubscriptionPlanBindingItems(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Bindings = items
		out[i].BindingCount = len(items)
	}
	return out, nil
}

func (s *Store) UpdateSubscriptionPlan(ctx context.Context, planID string, params CreateSubscriptionPlanParams) (model.SubscriptionPlan, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE subscription_plans SET name = ?, modified_at = ? WHERE id = ?`, params.Name, now, planID)
	if err != nil {
		return model.SubscriptionPlan{}, fmt.Errorf("update subscription plan: %w", err)
	}
	if affected, err := res.RowsAffected(); err == nil && affected == 0 {
		return model.SubscriptionPlan{}, ErrNotFound
	}
	if err := s.replaceSubscriptionPlanBindingItems(ctx, planID, params.BindingIDs); err != nil {
		return model.SubscriptionPlan{}, err
	}
	_ = s.Audit(ctx, "admin", "update", "subscription_plan", planID, params.Name)
	return s.GetSubscriptionPlan(ctx, planID)
}

func (s *Store) DeleteSubscriptionPlan(ctx context.Context, planID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM user_subscription_plans WHERE subscription_plan_id = ?`, planID); err != nil {
		return fmt.Errorf("delete user subscription plan links: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM subscription_plan_binding_items WHERE subscription_plan_id = ?`, planID); err != nil {
		return fmt.Errorf("delete subscription plan bindings: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM subscription_plans WHERE id = ?`, planID)
	if err != nil {
		return fmt.Errorf("delete subscription plan: %w", err)
	}
	if affected, err := res.RowsAffected(); err == nil && affected == 0 {
		return ErrNotFound
	}
	_ = s.Audit(ctx, "admin", "delete", "subscription_plan", planID, "")
	return nil
}

func (s *Store) UpdateUserSubscription(ctx context.Context, userID, name string, expiresAt time.Time) (model.Subscription, error) {
	current, err := s.currentSubscriptionByUser(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return s.CreateSubscription(ctx, CreateSubscriptionParams{
			UserID:    userID,
			Name:      name,
			ExpiresAt: expiresAt,
		})
	}
	if err != nil {
		return model.Subscription{}, err
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(
		ctx,
		`UPDATE subscriptions SET name = ?, expires_at = ?, modified_at = ? WHERE id = ?`,
		name,
		expiresAt.UTC(),
		now,
		current.ID,
	)
	if err != nil {
		return model.Subscription{}, fmt.Errorf("update user subscription: %w", err)
	}
	_ = s.Audit(ctx, "admin", "update", "subscription", current.ID, name)
	return s.currentSubscriptionByUser(ctx, userID)
}

func (s *Store) SetUserSubscriptionStatus(ctx context.Context, userID, status string) (model.Subscription, error) {
	current, err := s.currentSubscriptionByUser(ctx, userID)
	if err != nil {
		return model.Subscription{}, err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(
		ctx,
		`UPDATE subscriptions SET status = ?, modified_at = ? WHERE id = ?`,
		status,
		now,
		current.ID,
	)
	if err != nil {
		return model.Subscription{}, fmt.Errorf("set subscription status: %w", err)
	}
	_ = s.Audit(ctx, "admin", "status", "subscription", current.ID, status)
	return s.currentSubscriptionByUser(ctx, userID)
}

func (s *Store) ExtendUserSubscription(ctx context.Context, userID string, days int) (model.Subscription, error) {
	current, err := s.currentSubscriptionByUser(ctx, userID)
	if err != nil {
		return model.Subscription{}, err
	}
	base := current.ExpiresAt
	now := time.Now().UTC()
	if base.Before(now) {
		base = now
	}
	return s.UpdateUserSubscription(ctx, userID, current.Name, base.Add(time.Duration(days)*24*time.Hour))
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
		RealityPrivateKey:      params.RealityPrivateKey,
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
	subs, err := s.ListSubscriptionPlans(ctx)
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

	if err := s.hydrateSubscriptionAccess(ctx, &portal.Subscription); err != nil {
		return PortalData{}, err
	}
	items := portal.Subscription.Bindings

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
	selectedBindingIDs := make(map[string]struct{}, len(items))
	selectedNodeIDs := make(map[string]struct{}, len(items))
	selectedInboundIDs := make(map[string]struct{}, len(items))
	for _, item := range items {
		selectedBindingIDs[item.NodeInboundBindingID] = struct{}{}
		selectedNodeIDs[item.NodeID] = struct{}{}
		selectedInboundIDs[item.InboundProfileID] = struct{}{}
	}

	for _, node := range nodes {
		if len(selectedNodeIDs) == 0 {
			continue
		}
		if _, ok := selectedNodeIDs[node.ID]; ok {
			portal.Nodes = append(portal.Nodes, node)
		}
	}
	for _, inbound := range inbounds {
		if len(selectedInboundIDs) == 0 {
			continue
		}
		if _, ok := selectedInboundIDs[inbound.ID]; ok {
			portal.Inbounds = append(portal.Inbounds, inbound)
		}
	}
	for _, binding := range bindings {
		if len(selectedBindingIDs) == 0 {
			continue
		}
		if _, ok := selectedBindingIDs[binding.ID]; ok {
			portal.Bindings = append(portal.Bindings, binding)
		}
	}
	return portal, nil
}

func (s *Store) activeSubscriptionUsersByBinding(ctx context.Context, users []model.User) (map[string][]model.User, error) {
	userByID := make(map[string]model.User, len(users))
	for _, user := range users {
		userByID[user.ID] = user
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT s.user_id, spbi.node_inbound_binding_id
		FROM subscriptions s
		JOIN user_subscription_plans usp ON usp.subscription_id = s.id
		JOIN subscription_plan_binding_items spbi ON spbi.subscription_plan_id = usp.subscription_plan_id
		WHERE s.status = 'active' AND s.expires_at > ?
		UNION
		SELECT s.user_id, sbi.node_inbound_binding_id
		FROM subscriptions s
		JOIN subscription_binding_items sbi ON sbi.subscription_id = s.id
		WHERE s.status = 'active' AND s.expires_at > ?`,
		time.Now().UTC(),
		time.Now().UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("query active subscription users by binding: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]model.User)
	seen := make(map[string]map[string]struct{})
	for rows.Next() {
		var userID, bindingID string
		if err := rows.Scan(&userID, &bindingID); err != nil {
			return nil, fmt.Errorf("scan active subscription user binding: %w", err)
		}
		user, ok := userByID[userID]
		if !ok {
			continue
		}
		if seen[bindingID] == nil {
			seen[bindingID] = make(map[string]struct{})
		}
		if _, ok := seen[bindingID][userID]; ok {
			continue
		}
		seen[bindingID][userID] = struct{}{}
		out[bindingID] = append(out[bindingID], user)
	}
	return out, rows.Err()
}

func (s *Store) NodeBundle(ctx context.Context, nodeID string) (model.Node, []model.InboundProfile, []model.TopologyLink, []model.Subscription, []model.User, error) {
	node, err := s.GetNode(ctx, nodeID)
	if err != nil {
		return model.Node{}, nil, nil, nil, nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT b.id, p.id, p.name, p.protocol, p.listen_host, p.listen_port, p.transport, p.server_name, p.public_host, p.path, p.password, p.reality_public_key, p.reality_private_key, p.reality_handshake_server, p.reality_handshake_port, p.reality_short_id, p.tls_mode, p.tls_cert_path, p.tls_key_path, p.shadowsocks_method, p.metadata_json, p.created_at, p.modified_at
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
	var bindingIDs []string
	for rows.Next() {
		var item model.InboundProfile
		var metadataJSON string
		var bindingID string
		if err := rows.Scan(&bindingID, &item.ID, &item.Name, &item.Protocol, &item.ListenHost, &item.ListenPort, &item.Transport, &item.ServerName, &item.PublicHost, &item.Path, &item.Password, &item.RealityPubKey, &item.RealityPrivateKey, &item.RealityHandshakeServer, &item.RealityHandshakePort, &item.RealityShort, &item.TLSMode, &item.TLSCertPath, &item.TLSKeyPath, &item.ShadowsocksMethod, &metadataJSON, &item.CreatedAt, &item.ModifiedAt); err != nil {
			return model.Node{}, nil, nil, nil, nil, fmt.Errorf("scan node inbound profile: %w", err)
		}
		if err := json.Unmarshal([]byte(metadataJSON), &item.Metadata); err != nil {
			item.Metadata = map[string]string{}
		}
		bindingIDs = append(bindingIDs, bindingID)
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
	usersByBinding, err := s.activeSubscriptionUsersByBinding(ctx, users)
	if err != nil {
		return model.Node{}, nil, nil, nil, nil, err
	}
	for i := range inbounds {
		assigned := usersByBinding[bindingIDs[i]]
		if assigned == nil {
			assigned = []model.User{}
		}
		inbounds[i].Users = assigned
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
