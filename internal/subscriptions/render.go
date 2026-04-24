package subscriptions

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"mgb-panel/internal/inboundrules"
	"mgb-panel/internal/model"
)

type Endpoint struct {
	NodeName string
	Host     string
	Profile  model.InboundProfile
	User     model.User
}

func RenderURI(ep Endpoint) string {
	host := ep.Host
	if host == "" {
		host = ep.Profile.PublicHost
	}
	if host == "" {
		host = ep.Profile.ServerName
	}
	if host == "" {
		host = ep.NodeName
	}

	profile, err := inboundrules.Normalize(ep.Profile)
	if err != nil {
		return ""
	}
	addr := net.JoinHostPort(host, strconv.Itoa(profile.ListenPort))

	switch profile.Protocol {
	case "vless":
		query := url.Values{}
		query.Set("encryption", "none")
		if profile.Transport != "" {
			query.Set("type", profile.Transport)
		}
		setTransportQuery(query, profile)
		if profile.TLSMode != "" {
			query.Set("security", profile.TLSMode)
		}
		if profile.ServerName != "" {
			query.Set("sni", profile.ServerName)
		}
		if profile.RealityPubKey != "" {
			query.Set("pbk", profile.RealityPubKey)
		}
		if profile.RealityShort != "" {
			query.Set("sid", profile.RealityShort)
		}
		return fmt.Sprintf("vless://%s@%s?%s#%s", ep.User.AccessKey, addr, query.Encode(), url.QueryEscape(profile.Name))
	case "trojan":
		query := url.Values{}
		if profile.TLSMode != "" {
			query.Set("security", profile.TLSMode)
		}
		if profile.ServerName != "" {
			query.Set("sni", profile.ServerName)
		}
		setTransportQuery(query, profile)
		return fmt.Sprintf("trojan://%s@%s?%s#%s", url.PathEscape(profile.Password), addr, query.Encode(), url.QueryEscape(profile.Name))
	case "hysteria2":
		query := url.Values{}
		if profile.ServerName != "" {
			query.Set("sni", profile.ServerName)
		}
		return fmt.Sprintf("hysteria2://%s@%s?%s#%s", url.PathEscape(profile.Password), addr, query.Encode(), url.QueryEscape(profile.Name))
	case "shadowsocks":
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(profile.ShadowsocksMethod + ":" + profile.Password))
		return fmt.Sprintf("ss://%s@%s#%s", userinfo, addr, url.QueryEscape(profile.Name))
	default:
		return fmt.Sprintf("%s://%s#%s", profile.Protocol, addr, url.QueryEscape(profile.Name))
	}
}

func setTransportQuery(query url.Values, profile model.InboundProfile) {
	switch profile.Transport {
	case "grpc":
		if profile.Path != "" {
			query.Set("serviceName", profile.Path)
		}
	case "ws", "http", "httpupgrade":
		if profile.Path != "" {
			query.Set("path", profile.Path)
		}
	}
}
