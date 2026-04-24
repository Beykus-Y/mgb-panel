package subscriptions

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

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

	switch strings.ToLower(ep.Profile.Protocol) {
	case "vless":
		query := url.Values{}
		query.Set("encryption", "none")
		if ep.Profile.Transport != "" {
			query.Set("type", ep.Profile.Transport)
		}
		if ep.Profile.Path != "" {
			query.Set("path", ep.Profile.Path)
		}
		if ep.Profile.TLSMode != "" {
			query.Set("security", strings.ToLower(ep.Profile.TLSMode))
		}
		if ep.Profile.ServerName != "" {
			query.Set("sni", ep.Profile.ServerName)
		}
		if ep.Profile.RealityPubKey != "" {
			query.Set("pbk", ep.Profile.RealityPubKey)
		}
		if ep.Profile.RealityShort != "" {
			query.Set("sid", ep.Profile.RealityShort)
		}
		return fmt.Sprintf(
			"vless://%s@%s:%d?%s#%s",
			ep.User.AccessKey,
			host,
			ep.Profile.ListenPort,
			query.Encode(),
			url.QueryEscape(ep.Profile.Name),
		)
	case "trojan":
		query := url.Values{}
		if ep.Profile.ServerName != "" {
			query.Set("sni", ep.Profile.ServerName)
		}
		return fmt.Sprintf(
			"trojan://%s@%s:%d?%s#%s",
			url.QueryEscape(ep.Profile.Password),
			host,
			ep.Profile.ListenPort,
			query.Encode(),
			url.QueryEscape(ep.Profile.Name),
		)
	case "hysteria2":
		query := url.Values{}
		if ep.Profile.ServerName != "" {
			query.Set("sni", ep.Profile.ServerName)
		}
		if ep.Profile.Password != "" {
			query.Set("password", ep.Profile.Password)
		}
		return fmt.Sprintf(
			"hysteria2://%s:%d?%s#%s",
			host,
			ep.Profile.ListenPort,
			query.Encode(),
			url.QueryEscape(ep.Profile.Name),
		)
	case "shadowsocks":
		return fmt.Sprintf(
			"ss://%s@%s:%s#%s",
			url.QueryEscape(ep.Profile.Password),
			host,
			strconv.Itoa(ep.Profile.ListenPort),
			url.QueryEscape(ep.Profile.Name),
		)
	default:
		return fmt.Sprintf("%s://%s:%d#%s", ep.Profile.Protocol, host, ep.Profile.ListenPort, url.QueryEscape(ep.Profile.Name))
	}
}
