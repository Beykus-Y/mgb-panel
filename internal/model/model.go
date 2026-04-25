package model

import "time"

type Node struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Address        string    `json:"address"`
	IsLocal        bool      `json:"is_local"`
	Role           string    `json:"role"`
	EnrollToken    string    `json:"enroll_token,omitempty"`
	Status         string    `json:"status"`
	LastHeartbeat  time.Time `json:"last_heartbeat"`
	LastSeenIP     string    `json:"last_seen_ip"`
	ActiveRevision int       `json:"active_revision"`
	LastApplyError string    `json:"last_apply_error"`
	CertSerial     string    `json:"cert_serial"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type User struct {
	ID                           string    `json:"id"`
	Name                         string    `json:"name"`
	Email                        string    `json:"email"`
	Telegram                     string    `json:"telegram"`
	Note                         string    `json:"note"`
	AccessKey                    string    `json:"access_key"`
	CurrentSubscriptionID        string    `json:"current_subscription_id,omitempty"`
	CurrentSubscriptionName      string    `json:"current_subscription_name,omitempty"`
	CurrentSubscriptionPlanIDs   []string  `json:"current_subscription_plan_ids,omitempty"`
	CurrentSubscriptionPlanNames []string  `json:"current_subscription_plan_names,omitempty"`
	CurrentSubscriptionStatus    string    `json:"current_subscription_status,omitempty"`
	CurrentSubscriptionToken     string    `json:"current_subscription_token,omitempty"`
	CurrentSubscriptionExpiresAt time.Time `json:"current_subscription_expires_at,omitempty"`
	CreatedAt                    time.Time `json:"created_at"`
	ModifiedAt                   time.Time `json:"modified_at"`
}

type Subscription struct {
	ID           string                    `json:"id"`
	UserID       string                    `json:"user_id"`
	Name         string                    `json:"name"`
	Status       string                    `json:"status"`
	ExpiresAt    time.Time                 `json:"expires_at"`
	Token        string                    `json:"token,omitempty"`
	PlanIDs      []string                  `json:"plan_ids,omitempty"`
	PlanNames    []string                  `json:"plan_names,omitempty"`
	Plans        []SubscriptionPlan        `json:"plans,omitempty"`
	BindingCount int                       `json:"binding_count"`
	Bindings     []SubscriptionBindingItem `json:"bindings,omitempty"`
	CreatedAt    time.Time                 `json:"created_at"`
	ModifiedAt   time.Time                 `json:"modified_at"`
}

type SubscriptionPlan struct {
	ID           string                    `json:"id"`
	Name         string                    `json:"name"`
	BindingCount int                       `json:"binding_count"`
	Bindings     []SubscriptionBindingItem `json:"bindings,omitempty"`
	CreatedAt    time.Time                 `json:"created_at"`
	ModifiedAt   time.Time                 `json:"modified_at"`
}

type SubscriptionBindingItem struct {
	ID                   string `json:"id"`
	SubscriptionID       string `json:"subscription_id"`
	SubscriptionPlanID   string `json:"subscription_plan_id"`
	NodeInboundBindingID string `json:"node_inbound_binding_id"`
	NodeID               string `json:"node_id"`
	NodeName             string `json:"node_name"`
	NodeAddress          string `json:"node_address"`
	InboundProfileID     string `json:"inbound_profile_id"`
	InboundName          string `json:"inbound_name"`
	Protocol             string `json:"protocol"`
	ListenPort           int    `json:"listen_port"`
	Transport            string `json:"transport"`
	TLSMode              string `json:"tls_mode"`
	PublicHost           string `json:"public_host"`
}

type InboundProfile struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	Protocol               string            `json:"protocol"`
	ListenHost             string            `json:"listen_host"`
	ListenPort             int               `json:"listen_port"`
	Transport              string            `json:"transport"`
	ServerName             string            `json:"server_name"`
	PublicHost             string            `json:"public_host"`
	Path                   string            `json:"path"`
	Password               string            `json:"password"`
	RealityPubKey          string            `json:"reality_public_key"`
	RealityPrivateKey      string            `json:"reality_private_key"`
	RealityHandshakeServer string            `json:"reality_handshake_server"`
	RealityHandshakePort   int               `json:"reality_handshake_port"`
	RealityShort           string            `json:"reality_short_id"`
	TLSMode                string            `json:"tls_mode"`
	TLSCertPath            string            `json:"tls_cert_path"`
	TLSKeyPath             string            `json:"tls_key_path"`
	ShadowsocksMethod      string            `json:"shadowsocks_method"`
	Metadata               map[string]string `json:"metadata"`
	Users                  []User            `json:"users,omitempty"`
	CreatedAt              time.Time         `json:"created_at"`
	ModifiedAt             time.Time         `json:"modified_at"`
}

type NodeInboundBinding struct {
	ID               string    `json:"id"`
	NodeID           string    `json:"node_id"`
	InboundProfileID string    `json:"inbound_profile_id"`
	CreatedAt        time.Time `json:"created_at"`
}

type TopologyLink struct {
	ID           string    `json:"id"`
	SourceNodeID string    `json:"source_node_id"`
	TargetNodeID string    `json:"target_node_id"`
	Role         string    `json:"role"`
	Transport    string    `json:"transport"`
	ListenPort   int       `json:"listen_port"`
	EndpointHost string    `json:"endpoint_host"`
	EndpointPort int       `json:"endpoint_port"`
	AllowedCIDRs string    `json:"allowed_cidrs"`
	CreatedAt    time.Time `json:"created_at"`
}

type RoutingPolicy struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Mode        string    `json:"mode"`
	CreatedAt   time.Time `json:"created_at"`
}

type ConfigRevision struct {
	ID         string    `json:"id"`
	NodeID     string    `json:"node_id"`
	Revision   int       `json:"revision"`
	ConfigJSON string    `json:"config_json"`
	ConfigHash string    `json:"config_hash"`
	Applied    bool      `json:"applied"`
	CreatedAt  time.Time `json:"created_at"`
}

type AuditEvent struct {
	ID         string    `json:"id"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	Details    string    `json:"details"`
	CreatedAt  time.Time `json:"created_at"`
}

type Dashboard struct {
	Nodes         []Node
	Users         []User
	Subscriptions []SubscriptionPlan
	Inbounds      []InboundProfile
	Bindings      []NodeInboundBinding
	TopologyLinks []TopologyLink
	Revisions     []ConfigRevision
}
