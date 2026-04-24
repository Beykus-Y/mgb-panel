package inboundrules

import (
	"fmt"
	"regexp"
	"strings"

	"mgb-panel/internal/model"
)

const DefaultShadowsocksMethod = "chacha20-ietf-poly1305"

var shortIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{1,16}$`)

func Normalize(profile model.InboundProfile) (model.InboundProfile, error) {
	p := profile
	p.Name = strings.TrimSpace(p.Name)
	p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	p.ListenHost = strings.TrimSpace(p.ListenHost)
	p.Transport = strings.ToLower(strings.TrimSpace(p.Transport))
	p.TLSMode = strings.ToLower(strings.TrimSpace(p.TLSMode))
	p.ServerName = strings.TrimSpace(p.ServerName)
	p.PublicHost = strings.TrimSpace(p.PublicHost)
	p.Path = strings.TrimSpace(p.Path)
	p.Password = strings.TrimSpace(p.Password)
	p.RealityPubKey = strings.TrimSpace(p.RealityPubKey)
	p.RealityPrivateKey = strings.TrimSpace(p.RealityPrivateKey)
	p.RealityHandshakeServer = strings.TrimSpace(p.RealityHandshakeServer)
	p.RealityShort = strings.TrimSpace(p.RealityShort)
	p.TLSCertPath = strings.TrimSpace(p.TLSCertPath)
	p.TLSKeyPath = strings.TrimSpace(p.TLSKeyPath)
	p.ShadowsocksMethod = strings.TrimSpace(p.ShadowsocksMethod)

	if p.Name == "" {
		return p, fmt.Errorf("name is required")
	}
	if p.Protocol == "" {
		p.Protocol = "vless"
	}
	if p.ListenHost == "" {
		p.ListenHost = "::"
	}
	if p.ListenPort < 1 || p.ListenPort > 65535 {
		return p, fmt.Errorf("listen port must be between 1 and 65535")
	}
	if p.Transport == "tcp" {
		p.Transport = ""
	}
	if p.TLSMode == "reality" && p.RealityHandshakePort == 0 {
		p.RealityHandshakePort = 443
	}

	switch p.Protocol {
	case "vless":
		if err := validateV2RayTransport(p); err != nil {
			return p, err
		}
		if err := validateTLS(p, true); err != nil {
			return p, err
		}
	case "trojan":
		if p.Password == "" {
			return p, fmt.Errorf("trojan password is required")
		}
		if p.TLSMode == "" {
			return p, fmt.Errorf("trojan requires TLS or REALITY")
		}
		if err := validateV2RayTransport(p); err != nil {
			return p, err
		}
		if err := validateTLS(p, true); err != nil {
			return p, err
		}
	case "hysteria2":
		if p.Password == "" {
			return p, fmt.Errorf("hysteria2 password is required")
		}
		if p.Transport != "" {
			return p, fmt.Errorf("hysteria2 does not support V2Ray transport")
		}
		if p.TLSMode != "tls" {
			return p, fmt.Errorf("hysteria2 requires TLS with certificate paths")
		}
		if err := validateTLS(p, false); err != nil {
			return p, err
		}
	case "shadowsocks":
		if p.Password == "" {
			return p, fmt.Errorf("shadowsocks password is required")
		}
		if p.Transport != "" {
			return p, fmt.Errorf("shadowsocks does not support V2Ray transport")
		}
		if p.TLSMode != "" {
			return p, fmt.Errorf("shadowsocks TLS is not supported by this profile")
		}
		if p.ShadowsocksMethod == "" {
			p.ShadowsocksMethod = DefaultShadowsocksMethod
		}
	default:
		return p, fmt.Errorf("unsupported protocol %q", p.Protocol)
	}

	return p, nil
}

func BuildTransport(profile model.InboundProfile) map[string]any {
	switch profile.Transport {
	case "ws":
		transport := map[string]any{"type": "ws"}
		if profile.Path != "" {
			transport["path"] = profile.Path
		}
		return transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if profile.Path != "" {
			transport["service_name"] = profile.Path
		}
		return transport
	case "httpupgrade":
		transport := map[string]any{"type": "httpupgrade"}
		if profile.Path != "" {
			transport["path"] = profile.Path
		}
		return transport
	case "http":
		transport := map[string]any{"type": "http"}
		if profile.Path != "" {
			transport["path"] = profile.Path
		}
		return transport
	case "quic":
		return map[string]any{"type": "quic"}
	default:
		return nil
	}
}

func BuildTLS(profile model.InboundProfile) map[string]any {
	if profile.TLSMode == "" {
		return nil
	}
	tlsBlock := map[string]any{"enabled": true}
	if profile.ServerName != "" {
		tlsBlock["server_name"] = profile.ServerName
	}
	if profile.TLSMode == "tls" {
		tlsBlock["certificate_path"] = profile.TLSCertPath
		tlsBlock["key_path"] = profile.TLSKeyPath
		return tlsBlock
	}
	tlsBlock["reality"] = map[string]any{
		"enabled": true,
		"handshake": map[string]any{
			"server":      profile.RealityHandshakeServer,
			"server_port": profile.RealityHandshakePort,
		},
		"private_key": profile.RealityPrivateKey,
		"short_id":    []string{profile.RealityShort},
	}
	return tlsBlock
}

func SupportsUserList(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "vless", "trojan", "hysteria2":
		return true
	default:
		return false
	}
}

func validateV2RayTransport(profile model.InboundProfile) error {
	switch profile.Transport {
	case "", "ws", "grpc", "httpupgrade", "http", "quic":
		return nil
	default:
		return fmt.Errorf("transport %q is not supported for %s", profile.Transport, profile.Protocol)
	}
}

func validateTLS(profile model.InboundProfile, allowReality bool) error {
	switch profile.TLSMode {
	case "":
		return nil
	case "tls":
		if profile.TLSCertPath == "" || profile.TLSKeyPath == "" {
			return fmt.Errorf("tls certificate and key paths are required")
		}
		return nil
	case "reality":
		if !allowReality {
			return fmt.Errorf("REALITY is not supported for %s", profile.Protocol)
		}
		if profile.RealityPrivateKey == "" {
			return fmt.Errorf("REALITY private key is required")
		}
		if profile.RealityPubKey == "" {
			return fmt.Errorf("REALITY public key is required for subscriptions")
		}
		if profile.RealityHandshakeServer == "" {
			return fmt.Errorf("REALITY handshake server is required")
		}
		if profile.RealityHandshakePort == 0 {
			profile.RealityHandshakePort = 443
		}
		if profile.RealityHandshakePort < 1 || profile.RealityHandshakePort > 65535 {
			return fmt.Errorf("REALITY handshake port must be between 1 and 65535")
		}
		if !shortIDPattern.MatchString(profile.RealityShort) {
			return fmt.Errorf("REALITY short id must be 1-16 hex characters")
		}
		return nil
	default:
		return fmt.Errorf("unsupported TLS mode %q", profile.TLSMode)
	}
}
