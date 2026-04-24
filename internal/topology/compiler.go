package topology

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"mgb-panel/internal/model"
)

type CompiledNode struct {
	Node     model.Node
	Revision string
	Config   []byte
}

func CompileNodeConfig(node model.Node, inbounds []model.InboundProfile, links []model.TopologyLink, users []model.User) ([]byte, error) {
	outbounds := []map[string]any{
		{
			"type": "direct",
			"tag":  "direct",
		},
		{
			"type": "block",
			"tag":  "block",
		},
	}

	configInbounds := make([]map[string]any, 0, len(inbounds))
	for _, inbound := range inbounds {
		usersBlock := make([]map[string]any, 0, len(users))
		for _, user := range users {
			switch strings.ToLower(inbound.Protocol) {
			case "vless":
				usersBlock = append(usersBlock, map[string]any{"uuid": user.AccessKey, "flow": ""})
			case "trojan", "hysteria2", "shadowsocks":
				usersBlock = append(usersBlock, map[string]any{"name": user.Name, "password": inbound.Password})
			}
		}

		item := map[string]any{
			"type":        inbound.Protocol,
			"tag":         inbound.ID,
			"listen":      defaultString(inbound.ListenHost, "::"),
			"listen_port": inbound.ListenPort,
		}
		if len(usersBlock) > 0 {
			item["users"] = usersBlock
		}
		if inbound.Transport != "" {
			item["transport"] = map[string]any{"type": inbound.Transport, "path": inbound.Path}
		}
		if inbound.TLSMode != "" {
			tlsBlock := map[string]any{
				"enabled":     true,
				"server_name": inbound.ServerName,
			}
			if strings.EqualFold(inbound.TLSMode, "reality") {
				tlsBlock["reality"] = map[string]any{
					"enabled":    true,
					"public_key": inbound.RealityPubKey,
					"short_id":   inbound.RealityShort,
				}
			}
			item["tls"] = tlsBlock
		}
		configInbounds = append(configInbounds, item)
	}

	for _, link := range links {
		peer := link.TargetNodeID
		if link.TargetNodeID == node.ID {
			peer = link.SourceNodeID
		}
		outbounds = append(outbounds, map[string]any{
			"type":            "wireguard",
			"tag":             link.ID,
			"server":          defaultString(link.EndpointHost, peer),
			"server_port":     link.EndpointPort,
			"local_address":   []string{"10.10.0.2/32"},
			"peer_public_key": "panel-generated",
			"allowed_ips":     splitCIDRs(link.AllowedCIDRs),
			"mtu":             1380,
		})
	}

	rules := make([]map[string]any, 0, len(links)+1)
	for _, link := range links {
		rules = append(rules, map[string]any{
			"outbound": link.ID,
			"ip_cidr":  splitCIDRs(link.AllowedCIDRs),
		})
	}
	rules = append(rules, map[string]any{"outbound": "direct"})

	payload := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"inbounds":  configInbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"auto_detect_interface": true,
			"rules":                 rules,
		},
		"experimental": map[string]any{
			"cache_file": map[string]any{
				"enabled": true,
				"path":    "cache.db",
			},
		},
	}
	return marshalStable(payload)
}

func splitCIDRs(raw string) []string {
	if raw == "" {
		return []string{"0.0.0.0/0", "::/0"}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return []string{"0.0.0.0/0", "::/0"}
	}
	return out
}

func marshalStable(v any) ([]byte, error) {
	normalized, err := normalize(v)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return out, nil
}

func normalize(v any) (any, error) {
	switch typed := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(typed))
		for _, key := range keys {
			item, err := normalize(typed[key])
			if err != nil {
				return nil, err
			}
			out[key] = item
		}
		return out, nil
	case []map[string]any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			norm, err := normalize(item)
			if err != nil {
				return nil, err
			}
			out = append(out, norm)
		}
		return out, nil
	case []string, string, int, bool, nil:
		return typed, nil
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			norm, err := normalize(item)
			if err != nil {
				return nil, err
			}
			out = append(out, norm)
		}
		return out, nil
	default:
		return typed, nil
	}
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
