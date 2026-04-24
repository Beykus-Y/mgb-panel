package controlplane

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mgb-panel/internal/database"
	"mgb-panel/internal/inboundrules"
	"mgb-panel/internal/model"
	"mgb-panel/internal/pki"
	"mgb-panel/internal/secret"
	"mgb-panel/internal/subscriptions"
	"mgb-panel/internal/topology"
)

//go:embed templates/*.html assets/*.sh
var templateFS embed.FS

type Server struct {
	store      *database.Store
	authority  *pki.Authority
	baseURL    string
	listenAddr string
	dataDir    string
	singboxBin string
	localPoll  time.Duration
	templates  *template.Template
	httpServer *http.Server
}

type Config struct {
	ListenAddr    string
	BaseURL       string
	DataDir       string
	SingboxBinary string
	LocalPoll     time.Duration
}

type adminPageData struct {
	BaseURL          string
	EffectiveBaseURL string
	CAFingerprint    string
	Dashboard        model.Dashboard
	Page             string
	NodeNames        map[string]string
	UserNames        map[string]string
	InboundNames     map[string]string
	BindingCatalog   []model.SubscriptionBindingItem
	LocalNode        *model.Node
}

func New(store *database.Store, authority *pki.Authority, cfg Config) (*Server, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"pageTitle":              pageTitle,
		"pageDescription":        pageDescription,
		"statusLabel":            statusLabel,
		"roleLabel":              roleLabel,
		"protocolLabel":          protocolLabel,
		"transportLabel":         transportLabel,
		"tlsModeLabel":           tlsModeLabel,
		"formatDate":             formatDate,
		"formatDateTime":         formatDateTime,
		"formatDateTimeInput":    formatDateTimeInput,
		"hasSubscriptionBinding": hasSubscriptionBinding,
		"nodeInstallCommand":     nodeInstallCommand,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	poll := cfg.LocalPoll
	if poll <= 0 {
		poll = 20 * time.Second
	}
	srv := &Server{
		store:      store,
		authority:  authority,
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		listenAddr: cfg.ListenAddr,
		dataDir:    cfg.DataDir,
		singboxBin: cfg.SingboxBinary,
		localPoll:  poll,
		templates:  tmpl,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleDashboard)
	mux.HandleFunc("/overview", srv.handleAdminPage("overview"))
	mux.HandleFunc("/nodes", srv.handleAdminPage("nodes"))
	mux.HandleFunc("/users", srv.handleAdminPage("users"))
	mux.HandleFunc("/subscriptions", srv.handleAdminPage("subscriptions"))
	mux.HandleFunc("/inbounds", srv.handleAdminPage("inbounds"))
	mux.HandleFunc("/bindings", srv.handleAdminPage("bindings"))
	mux.HandleFunc("/topology", srv.handleAdminPage("topology"))
	mux.HandleFunc("/revisions", srv.handleAdminPage("revisions"))
	mux.HandleFunc("/install/node.sh", srv.handleInstallScript("assets/install-node.sh"))
	mux.HandleFunc("/install/panel.sh", srv.handleInstallScript("assets/install-panel.sh"))
	mux.HandleFunc("/admin/nodes", srv.handleCreateNodeForm)
	mux.HandleFunc("/admin/users", srv.handleCreateUserForm)
	mux.HandleFunc("/admin/users/update", srv.handleUpdateUserForm)
	mux.HandleFunc("/admin/users/freeze", srv.handleFreezeUserForm)
	mux.HandleFunc("/admin/users/activate", srv.handleActivateUserForm)
	mux.HandleFunc("/admin/users/extend", srv.handleExtendUserForm)
	mux.HandleFunc("/admin/subscriptions", srv.handleCreateSubscriptionForm)
	mux.HandleFunc("/admin/inbounds", srv.handleCreateInboundForm)
	mux.HandleFunc("/admin/bindings", srv.handleCreateBindingForm)
	mux.HandleFunc("/admin/topology", srv.handleCreateTopologyForm)
	mux.HandleFunc("/admin/nodes/enable-local", srv.handleEnableLocalNode)

	mux.HandleFunc("/api/admin/nodes", srv.handleAdminNodesAPI)
	mux.HandleFunc("/api/admin/users", srv.handleAdminUsersAPI)
	mux.HandleFunc("/api/admin/subscriptions", srv.handleAdminSubscriptionsAPI)
	mux.HandleFunc("/api/admin/inbounds", srv.handleAdminInboundsAPI)
	mux.HandleFunc("/api/admin/bindings", srv.handleAdminBindingsAPI)
	mux.HandleFunc("/api/admin/topology", srv.handleAdminTopologyAPI)
	mux.HandleFunc("/api/admin/revisions", srv.handleAdminRevisionsAPI)

	mux.HandleFunc("/api/pki/ca", srv.handleCAPEM)
	mux.HandleFunc("/api/node/enroll", srv.handleNodeEnroll)
	mux.HandleFunc("/api/node/heartbeat", srv.requireNodeMTLS(srv.handleNodeHeartbeat))
	mux.HandleFunc("/api/node/config", srv.requireNodeMTLS(srv.handleNodeConfig))
	mux.HandleFunc("/api/node/ack", srv.requireNodeMTLS(srv.handleNodeAck))

	mux.HandleFunc("/portal/", srv.handlePortal)
	mux.HandleFunc("/subscription/", srv.handleSubscriptionFeed)

	tlsConfig, err := authority.TLSConfig()
	if err != nil {
		return nil, err
	}
	srv.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		TLSConfig:    tlsConfig,
	}
	return srv, nil
}

func (s *Server) ListenAndServeTLS() error {
	return s.httpServer.ListenAndServeTLS("", "")
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.renderAdminPage(w, r, "overview")
}

func (s *Server) handleAdminPage(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.renderAdminPage(w, r, page)
	}
}

func (s *Server) renderAdminPage(w http.ResponseWriter, r *http.Request, page string) {
	dashboard, err := s.store.Dashboard(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := adminPageData{
		BaseURL:          s.baseURL,
		EffectiveBaseURL: s.effectiveBaseURL(r),
		CAFingerprint:    s.authority.FingerprintHex(),
		Dashboard:        dashboard,
		Page:             page,
		NodeNames:        make(map[string]string, len(dashboard.Nodes)),
		UserNames:        make(map[string]string, len(dashboard.Users)),
		InboundNames:     make(map[string]string, len(dashboard.Inbounds)),
	}
	for _, node := range dashboard.Nodes {
		data.NodeNames[node.ID] = node.Name
		if node.IsLocal {
			n := node
			data.LocalNode = &n
		}
	}
	for _, user := range dashboard.Users {
		data.UserNames[user.ID] = user.Name
	}
	for _, inbound := range dashboard.Inbounds {
		data.InboundNames[inbound.ID] = inbound.Name
	}
	for _, binding := range dashboard.Bindings {
		var (
			nodeName    = binding.NodeID
			nodeAddress string
			inboundName = binding.InboundProfileID
			publicHost  string
		)
		for _, node := range dashboard.Nodes {
			if node.ID == binding.NodeID {
				nodeName = node.Name
				nodeAddress = node.Address
				break
			}
		}
		for _, inbound := range dashboard.Inbounds {
			if inbound.ID == binding.InboundProfileID {
				inboundName = inbound.Name
				publicHost = inbound.PublicHost
				if publicHost == "" {
					publicHost = inbound.ServerName
				}
				break
			}
		}
		if publicHost == "" {
			publicHost = nodeAddress
		}
		if publicHost == "" {
			publicHost = nodeName
		}
		data.BindingCatalog = append(data.BindingCatalog, model.SubscriptionBindingItem{
			NodeInboundBindingID: binding.ID,
			NodeID:               binding.NodeID,
			NodeName:             nodeName,
			NodeAddress:          nodeAddress,
			InboundProfileID:     binding.InboundProfileID,
			InboundName:          inboundName,
			PublicHost:           publicHost,
		})
	}
	if err := s.templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleCreateNodeForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	role := defaultForm(r, "role", "edge")
	isLocal := r.FormValue("is_local") == "on"
	if _, err := s.store.CreateNode(r.Context(), database.CreateNodeParams{
		Name:    defaultForm(r, "name", "node"),
		Address: defaultForm(r, "address", ""),
		Role:    role,
		IsLocal: isLocal,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, adminRedirect(r, "/nodes"), http.StatusSeeOther)
}

func (s *Server) handleCreateUserForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := s.store.CreateUser(r.Context(), database.CreateUserParams{
		Name:     defaultForm(r, "name", "user"),
		Email:    defaultForm(r, "email", "user@example.com"),
		Telegram: strings.TrimSpace(r.FormValue("telegram")),
		Note:     strings.TrimSpace(r.FormValue("note")),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, adminRedirect(r, "/users"), http.StatusSeeOther)
}

func (s *Server) handleCreateSubscriptionForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	days, _ := strconv.Atoi(defaultForm(r, "days", "30"))
	if _, err := s.store.CreateSubscription(r.Context(), database.CreateSubscriptionParams{
		UserID:     r.FormValue("user_id"),
		Name:       defaultForm(r, "name", "default"),
		ExpiresAt:  time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour),
		BindingIDs: r.Form["binding_id"],
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, adminRedirect(r, "/subscriptions"), http.StatusSeeOther)
}

func (s *Server) handleCreateInboundForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	port, _ := strconv.Atoi(defaultForm(r, "listen_port", "443"))
	realityHandshakePort, _ := strconv.Atoi(defaultForm(r, "reality_handshake_port", "443"))
	params, err := normalizeInboundCreateParams(database.CreateInboundProfileParams{
		Name:                   defaultForm(r, "name", "default-inbound"),
		Protocol:               strings.ToLower(defaultForm(r, "protocol", "vless")),
		ListenHost:             defaultForm(r, "listen_host", "::"),
		ListenPort:             port,
		Transport:              r.FormValue("transport"),
		ServerName:             r.FormValue("server_name"),
		PublicHost:             r.FormValue("public_host"),
		Path:                   r.FormValue("path"),
		Password:               r.FormValue("password"),
		RealityPubKey:          r.FormValue("reality_public_key"),
		RealityPrivateKey:      r.FormValue("reality_private_key"),
		RealityHandshakeServer: r.FormValue("reality_handshake_server"),
		RealityHandshakePort:   realityHandshakePort,
		RealityShort:           r.FormValue("reality_short_id"),
		TLSMode:                r.FormValue("tls_mode"),
		TLSCertPath:            r.FormValue("tls_cert_path"),
		TLSKeyPath:             r.FormValue("tls_key_path"),
		ShadowsocksMethod:      r.FormValue("shadowsocks_method"),
		Metadata:               map[string]string{"created_by": "dashboard"},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := s.store.CreateInboundProfile(r.Context(), params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, adminRedirect(r, "/inbounds"), http.StatusSeeOther)
}

func (s *Server) handleUpdateUserForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := strings.TrimSpace(r.FormValue("user_id"))
	if _, err := s.store.UpdateUser(r.Context(), userID, database.CreateUserParams{
		Name:     defaultForm(r, "name", "user"),
		Email:    defaultForm(r, "email", "user@example.com"),
		Telegram: strings.TrimSpace(r.FormValue("telegram")),
		Note:     strings.TrimSpace(r.FormValue("note")),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	subscriptionName := strings.TrimSpace(r.FormValue("subscription_name"))
	expiresRaw := strings.TrimSpace(r.FormValue("subscription_expires_at"))
	if subscriptionName != "" && expiresRaw != "" {
		expiresAt, err := time.ParseInLocation("2006-01-02T15:04", expiresRaw, time.Local)
		if err != nil {
			http.Error(w, "invalid subscription expiry", http.StatusBadRequest)
			return
		}
		if _, err := s.store.UpdateUserSubscription(r.Context(), userID, subscriptionName, expiresAt.UTC()); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	http.Redirect(w, r, adminRedirect(r, "/users"), http.StatusSeeOther)
}

func (s *Server) handleFreezeUserForm(w http.ResponseWriter, r *http.Request) {
	s.handleUserSubscriptionStatus(w, r, "inactive", "/users")
}

func (s *Server) handleActivateUserForm(w http.ResponseWriter, r *http.Request) {
	s.handleUserSubscriptionStatus(w, r, "active", "/users")
}

func (s *Server) handleUserSubscriptionStatus(w http.ResponseWriter, r *http.Request, status, fallback string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := s.store.SetUserSubscriptionStatus(r.Context(), strings.TrimSpace(r.FormValue("user_id")), status); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, adminRedirect(r, fallback), http.StatusSeeOther)
}

func (s *Server) handleExtendUserForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	days, _ := strconv.Atoi(defaultForm(r, "days", "30"))
	if _, err := s.store.ExtendUserSubscription(r.Context(), strings.TrimSpace(r.FormValue("user_id")), maxInt(days, 1)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, adminRedirect(r, "/users"), http.StatusSeeOther)
}

func (s *Server) handleCreateBindingForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := s.store.CreateNodeInboundBinding(r.Context(), r.FormValue("node_id"), r.FormValue("inbound_profile_id")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, adminRedirect(r, "/bindings"), http.StatusSeeOther)
}

func (s *Server) handleCreateTopologyForm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	listenPort, _ := strconv.Atoi(defaultForm(r, "listen_port", "51820"))
	endpointPort, _ := strconv.Atoi(defaultForm(r, "endpoint_port", "51820"))
	endpointHost := strings.TrimSpace(r.FormValue("endpoint_host"))
	if endpointHost == "" {
		targetNode, err := s.store.GetNode(r.Context(), r.FormValue("target_node_id"))
		if err == nil {
			endpointHost = targetNode.Address
		}
	}
	if _, err := s.store.CreateTopologyLink(r.Context(), database.CreateTopologyLinkParams{
		SourceNodeID: r.FormValue("source_node_id"),
		TargetNodeID: r.FormValue("target_node_id"),
		Role:         defaultForm(r, "role", "relay"),
		Transport:    defaultForm(r, "transport", "wireguard"),
		ListenPort:   listenPort,
		EndpointHost: endpointHost,
		EndpointPort: endpointPort,
		AllowedCIDRs: defaultForm(r, "allowed_cidrs", "0.0.0.0/0, ::/0"),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, adminRedirect(r, "/topology"), http.StatusSeeOther)
}

func (s *Server) handleAdminNodesAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		nodes, err := s.store.ListNodes(r.Context())
		writeJSON(w, nodes, err)
	case http.MethodPost:
		var req struct {
			Name    string `json:"name"`
			Address string `json:"address"`
			Role    string `json:"role"`
			IsLocal bool   `json:"is_local"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		node, err := s.store.CreateNode(r.Context(), database.CreateNodeParams{Name: req.Name, Address: req.Address, Role: req.Role, IsLocal: req.IsLocal})
		writeJSON(w, node, err)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminUsersAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.store.ListUsers(r.Context())
		writeJSON(w, users, err)
	case http.MethodPost:
		var req struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Telegram string `json:"telegram"`
			Note     string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		user, err := s.store.CreateUser(r.Context(), database.CreateUserParams{Name: req.Name, Email: req.Email, Telegram: req.Telegram, Note: req.Note})
		writeJSON(w, user, err)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminSubscriptionsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		subs, err := s.store.ListSubscriptions(r.Context())
		writeJSON(w, subs, err)
	case http.MethodPost:
		var req struct {
			UserID     string   `json:"user_id"`
			Name       string   `json:"name"`
			Days       int      `json:"days"`
			BindingIDs []string `json:"binding_ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sub, err := s.store.CreateSubscription(r.Context(), database.CreateSubscriptionParams{
			UserID:     req.UserID,
			Name:       req.Name,
			ExpiresAt:  time.Now().UTC().Add(time.Duration(maxInt(req.Days, 1)) * 24 * time.Hour),
			BindingIDs: req.BindingIDs,
		})
		writeJSON(w, sub, err)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminInboundsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		inbounds, err := s.store.ListInboundProfiles(r.Context())
		writeJSON(w, inbounds, err)
	case http.MethodPost:
		var req database.CreateInboundProfileParams
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		params, err := normalizeInboundCreateParams(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		inbound, err := s.store.CreateInboundProfile(r.Context(), params)
		writeJSON(w, inbound, err)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminBindingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		bindings, err := s.store.ListBindings(r.Context())
		writeJSON(w, bindings, err)
	case http.MethodPost:
		var req struct {
			NodeID           string `json:"node_id"`
			InboundProfileID string `json:"inbound_profile_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		binding, err := s.store.CreateNodeInboundBinding(r.Context(), req.NodeID, req.InboundProfileID)
		writeJSON(w, binding, err)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminTopologyAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		links, err := s.store.ListTopologyLinks(r.Context())
		writeJSON(w, links, err)
	case http.MethodPost:
		var req database.CreateTopologyLinkParams
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		link, err := s.store.CreateTopologyLink(r.Context(), req)
		writeJSON(w, link, err)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminRevisionsAPI(w http.ResponseWriter, r *http.Request) {
	revisions, err := s.store.ListConfigRevisions(r.Context())
	writeJSON(w, revisions, err)
}

func (s *Server) handleCAPEM(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.authority.CAPEM())
}

func (s *Server) handleNodeEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		BootstrapToken string `json:"bootstrap_token"`
		CSR            string `json:"csr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node, err := s.store.EnrollNodeByToken(r.Context(), req.BootstrapToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	certPEM, serial, notAfter, err := s.authority.SignNodeCSR([]byte(req.CSR), node.ID, 180*24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.SaveNodeCertificate(r.Context(), node.ID, serial, string(certPEM), notAfter); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"node_id":     node.ID,
		"certificate": string(certPEM),
		"ca":          string(s.authority.CAPEM()),
		"not_after":   notAfter.UTC(),
		"fingerprint": s.authority.FingerprintHex(),
	}, nil)
}

func (s *Server) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request, nodeID string) {
	var req struct {
		Status   string `json:"status"`
		Revision int    `json:"revision"`
		Error    string `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Status == "" {
		req.Status = "healthy"
	}
	err := s.store.UpdateNodeStatus(r.Context(), nodeID, req.Status, req.Error, remoteIP(r.RemoteAddr), req.Revision)
	writeJSON(w, map[string]any{"ok": err == nil}, err)
}

func (s *Server) handleNodeConfig(w http.ResponseWriter, r *http.Request, nodeID string) {
	node, inbounds, links, subs, users, err := s.store.NodeBundle(r.Context(), nodeID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	activeUsers := make([]model.User, 0, len(users))
	userMap := make(map[string]model.User, len(users))
	activeUserIDs := make(map[string]struct{}, len(users))
	for _, user := range users {
		userMap[user.ID] = user
	}
	for _, sub := range subs {
		if _, seen := activeUserIDs[sub.UserID]; seen {
			continue
		}
		if user, ok := userMap[sub.UserID]; ok {
			activeUsers = append(activeUsers, user)
			activeUserIDs[sub.UserID] = struct{}{}
		}
	}

	configBytes, err := topology.CompileNodeConfig(node, inbounds, links, activeUsers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	revision, err := s.store.EnsureConfigRevision(r.Context(), nodeID, string(configBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	currentRevision, _ := strconv.Atoi(r.URL.Query().Get("current_revision"))
	resp := map[string]any{
		"node_id":  nodeID,
		"revision": revision.Revision,
		"changed":  revision.Revision > currentRevision,
	}
	if revision.Revision > currentRevision {
		resp["config"] = json.RawMessage(configBytes)
	}
	writeJSON(w, resp, nil)
}

func (s *Server) handleNodeAck(w http.ResponseWriter, r *http.Request, nodeID string) {
	var req struct {
		Revision int    `json:"revision"`
		Success  bool   `json:"success"`
		Error    string `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.store.MarkConfigApplied(r.Context(), nodeID, req.Revision, req.Success, req.Error)
	writeJSON(w, map[string]any{"ok": err == nil}, err)
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/portal/")
	portal, err := s.store.PortalDataByToken(r.Context(), token)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	type portalEndpoint struct {
		Node model.Node
		URI  string
	}
	var endpoints []portalEndpoint
	for _, binding := range portal.Bindings {
		var node model.Node
		var inbound model.InboundProfile
		nodeFound := false
		inboundFound := false
		for _, n := range portal.Nodes {
			if n.ID == binding.NodeID {
				node = n
				nodeFound = true
				break
			}
		}
		for _, ib := range portal.Inbounds {
			if ib.ID == binding.InboundProfileID {
				inbound = ib
				inboundFound = true
				break
			}
		}
		if !nodeFound || !inboundFound {
			continue
		}
		uri := subscriptions.RenderURI(subscriptions.Endpoint{
			NodeName: node.Name,
			Host:     publicHostForNode(node, inbound, r.Host),
			Profile:  inbound,
			User:     portal.User,
		})
		if uri == "" {
			continue
		}
		endpoints = append(endpoints, portalEndpoint{Node: node, URI: uri})
	}

	baseURL := s.effectiveBaseURL(r)
	data := map[string]any{
		"BaseURL":      s.baseURL,
		"Portal":       portal,
		"PortalURL":    baseURL + "/portal/" + token,
		"FeedURL":      baseURL + "/subscription/" + token,
		"ManualConfig": endpoints,
	}
	if err := s.templates.ExecuteTemplate(w, "portal.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleSubscriptionFeed(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/subscription/")
	portal, err := s.store.PortalDataByToken(r.Context(), token)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	lines := make([]string, 0, len(portal.Bindings))
	for _, binding := range portal.Bindings {
		var node model.Node
		var inbound model.InboundProfile
		okNode, okInbound := false, false
		for _, n := range portal.Nodes {
			if n.ID == binding.NodeID {
				node = n
				okNode = true
				break
			}
		}
		for _, ib := range portal.Inbounds {
			if ib.ID == binding.InboundProfileID {
				inbound = ib
				okInbound = true
				break
			}
		}
		if !okNode || !okInbound {
			continue
		}
		uri := subscriptions.RenderURI(subscriptions.Endpoint{
			NodeName: node.Name,
			Host:     publicHostForNode(node, inbound, r.Host),
			Profile:  inbound,
			User:     portal.User,
		})
		if uri != "" {
			lines = append(lines, uri)
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(strings.Join(lines, "\n")))
}

func (s *Server) requireNodeMTLS(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nodeID, err := pki.VerifyClientCertificate(r.TLS)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		next(w, r, nodeID)
	}
}

func writeJSON(w http.ResponseWriter, payload any, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func defaultForm(r *http.Request, key, fallback string) string {
	if err := r.ParseForm(); err != nil {
		return fallback
	}
	value := strings.TrimSpace(r.FormValue(key))
	if value == "" {
		return fallback
	}
	return value
}

func normalizeInboundCreateParams(params database.CreateInboundProfileParams) (database.CreateInboundProfileParams, error) {
	if err := applyInboundAutogen(&params); err != nil {
		return params, err
	}
	profile, err := inboundrules.Normalize(model.InboundProfile{
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
	})
	if err != nil {
		return params, err
	}
	params.Name = profile.Name
	params.Protocol = profile.Protocol
	params.ListenHost = profile.ListenHost
	params.ListenPort = profile.ListenPort
	params.Transport = profile.Transport
	params.ServerName = profile.ServerName
	params.PublicHost = profile.PublicHost
	params.Path = profile.Path
	params.Password = profile.Password
	params.RealityPubKey = profile.RealityPubKey
	params.RealityPrivateKey = profile.RealityPrivateKey
	params.RealityHandshakeServer = profile.RealityHandshakeServer
	params.RealityHandshakePort = profile.RealityHandshakePort
	params.RealityShort = profile.RealityShort
	params.TLSMode = profile.TLSMode
	params.TLSCertPath = profile.TLSCertPath
	params.TLSKeyPath = profile.TLSKeyPath
	params.ShadowsocksMethod = profile.ShadowsocksMethod
	return params, nil
}

func applyInboundAutogen(params *database.CreateInboundProfileParams) error {
	switch strings.ToLower(strings.TrimSpace(params.Protocol)) {
	case "trojan", "hysteria2", "shadowsocks":
		if strings.TrimSpace(params.Password) == "" {
			password, err := secret.Hex(12)
			if err != nil {
				return err
			}
			params.Password = password
		}
	}

	if strings.ToLower(strings.TrimSpace(params.TLSMode)) != "reality" {
		return nil
	}
	if strings.TrimSpace(params.RealityShort) == "" {
		shortID, err := secret.Hex(4)
		if err != nil {
			return err
		}
		params.RealityShort = shortID
	}
	if strings.TrimSpace(params.RealityHandshakeServer) == "" {
		params.RealityHandshakeServer = "www.cloudflare.com"
	}
	if params.RealityHandshakePort == 0 {
		params.RealityHandshakePort = 443
	}
	if strings.TrimSpace(params.RealityPrivateKey) != "" && strings.TrimSpace(params.RealityPubKey) != "" {
		return nil
	}

	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate reality keypair: %w", err)
	}
	params.RealityPrivateKey = base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
	params.RealityPubKey = base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	return nil
}

func (s *Server) handleInstallScript(assetPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := templateFS.ReadFile(assetPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write(body)
	}
}

func adminRedirect(r *http.Request, fallback string) string {
	switch defaultForm(r, "redirect_to", fallback) {
	case "/", "/overview", "/nodes", "/users", "/subscriptions", "/inbounds", "/bindings", "/topology", "/revisions":
		return defaultForm(r, "redirect_to", fallback)
	default:
		return fallback
	}
}

func publicHostForNode(node model.Node, inbound model.InboundProfile, requestHost string) string {
	if inbound.PublicHost != "" {
		return inbound.PublicHost
	}
	if inbound.ServerName != "" {
		return inbound.ServerName
	}
	if node.Address != "" {
		return node.Address
	}
	if strings.Contains(requestHost, ":") {
		host, _, found := strings.Cut(requestHost, ":")
		if found {
			return host
		}
	}
	return requestHost
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddr)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(started))
	})
}

func pageTitle(page string) string {
	switch page {
	case "overview":
		return "Обзор"
	case "nodes":
		return "Узлы"
	case "users":
		return "Пользователи"
	case "subscriptions":
		return "Подписки"
	case "inbounds":
		return "Инбаунды"
	case "bindings":
		return "Привязки"
	case "topology":
		return "Топология"
	case "revisions":
		return "Ревизии"
	default:
		return "Панель"
	}
}

func pageDescription(page string) string {
	switch page {
	case "overview":
		return "Сводка по control plane, CA и последним изменениям конфигурации."
	case "nodes":
		return "Управление узлами, их адресами, токенами bootstrap, CA и статусами heartbeat."
	case "users":
		return "База пользователей, для которых выпускаются ключи доступа и подписки."
	case "subscriptions":
		return "Подписки, сроки действия и ссылки на пользовательские порталы и feed."
	case "inbounds":
		return "Профили входящих подключений с выбором транспорта и режима TLS/REALITY."
	case "bindings":
		return "Связки между узлами и inbound-профилями, которые публикуются в конфиг."
	case "topology":
		return "Связи между узлами и транспорт для межузловой топологии."
	case "revisions":
		return "История сгенерированных ревизий конфигурации по узлам."
	default:
		return ""
	}
}

func statusLabel(status string) string {
	switch strings.ToLower(status) {
	case "pending":
		return "Ожидает"
	case "healthy":
		return "Работает"
	case "enrolled":
		return "Сертификат выдан"
	case "active":
		return "Активна"
	case "error":
		return "Ошибка"
	case "inactive":
		return "Неактивен"
	default:
		if status == "" {
			return "Неизвестно"
		}
		return strings.ToUpper(status[:1]) + status[1:]
	}
}

func roleLabel(role string) string {
	switch strings.ToLower(role) {
	case "edge":
		return "Edge"
	case "relay":
		return "Relay"
	case "egress":
		return "Egress"
	case "backup":
		return "Резерв"
	default:
		if role == "" {
			return "Не задана"
		}
		return role
	}
}

func protocolLabel(protocol string) string {
	switch strings.ToLower(protocol) {
	case "vless":
		return "VLESS"
	case "trojan":
		return "Trojan"
	case "hysteria2":
		return "Hysteria 2"
	case "shadowsocks":
		return "Shadowsocks"
	default:
		if protocol == "" {
			return "Не задан"
		}
		return strings.ToUpper(protocol)
	}
}

func transportLabel(transport string) string {
	switch strings.ToLower(transport) {
	case "":
		return "Без транспорта"
	case "ws":
		return "WebSocket"
	case "grpc":
		return "gRPC"
	case "httpupgrade":
		return "HTTPUpgrade"
	case "http":
		return "HTTP"
	case "quic":
		return "QUIC"
	case "tcp":
		return "TCP"
	case "wireguard":
		return "WireGuard"
	default:
		return transport
	}
}

func tlsModeLabel(mode string) string {
	switch strings.ToLower(mode) {
	case "":
		return "Без TLS"
	case "tls":
		return "TLS"
	case "reality":
		return "REALITY"
	default:
		return mode
	}
}

func formatDate(t time.Time) string {
	if t.IsZero() {
		return "не указано"
	}
	return t.UTC().Format("02.01.2006")
}

func formatDateTime(t time.Time) string {
	if t.IsZero() {
		return "никогда"
	}
	return t.UTC().Format("02.01.2006 15:04 UTC")
}

func formatDateTimeInput(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(time.Local).Format("2006-01-02T15:04")
}

func hasSubscriptionBinding(sub model.Subscription, bindingID string) bool {
	for _, item := range sub.Bindings {
		if item.NodeInboundBindingID == bindingID {
			return true
		}
	}
	return false
}

func nodeInstallCommand(baseURL, enrollToken, fingerprint string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	enrollToken = strings.TrimSpace(enrollToken)
	fingerprint = strings.TrimSpace(fingerprint)
	// -k is required because the panel uses a custom CA;
	// the script itself verifies the CA fingerprint before trusting anything.
	return fmt.Sprintf(
		"curl -fsSLk %s/install/node.sh | bash -s -- --panel-url %s --bootstrap-token %s --panel-fingerprint %s",
		baseURL,
		baseURL,
		enrollToken,
		fingerprint,
	)
}

// effectiveBaseURL returns the URL that the browser is actually using,
// falling back to request host when baseURL is a placeholder.
func (s *Server) effectiveBaseURL(r *http.Request) string {
	parsed, err := url.Parse(s.baseURL)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return requestBaseURL(r)
	}
	host := parsed.Hostname()
	if host == "localhost" || host == "127.0.0.1" ||
		strings.HasSuffix(host, ".example.com") ||
		strings.HasSuffix(host, ".example.org") ||
		host == "example.com" || host == "example.org" {
		return requestBaseURL(r)
	}
	return s.baseURL
}

func requestBaseURL(r *http.Request) string {
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		proto = "https"
	}
	if strings.Contains(host, ",") {
		host, _, _ = strings.Cut(host, ",")
		host = strings.TrimSpace(host)
	}
	if strings.Contains(proto, ",") {
		proto, _, _ = strings.Cut(proto, ",")
		proto = strings.TrimSpace(proto)
	}
	return proto + "://" + host
}

func (s *Server) handleEnableLocalNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.dataDir == "" {
		http.Error(w, "data dir is required to enable local node", http.StatusInternalServerError)
		return
	}
	dashboard, err := s.store.Dashboard(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var token string
	for _, node := range dashboard.Nodes {
		if !node.IsLocal {
			continue
		}
		token, err = s.store.IssueEnrollToken(r.Context(), node.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		break
	}
	if token == "" {
		node, err := s.store.CreateNode(r.Context(), database.CreateNodeParams{
			Name:    "local-panel",
			Address: "127.0.0.1",
			Role:    "edge",
			IsLocal: true,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		token = node.EnrollToken
	}
	if err := writeLocalNodeBootstrapToken(s.dataDir, token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/nodes", http.StatusSeeOther)
}

func writeLocalNodeBootstrapToken(dataDir, token string) error {
	dir := filepath.Join(dataDir, "local-node")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir local node dir: %w", err)
	}
	path := filepath.Join(dir, "bootstrap-token")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(token)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write local node bootstrap token: %w", err)
	}
	return nil
}
