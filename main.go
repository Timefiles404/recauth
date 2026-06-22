// recauth-launch — a downstream launcher for Claude Code, a faithful clone of how
// `reclaude <claude args>` launches the real CLI: it runs a LOCAL, NO-AUTH proxy port
// on 127.0.0.1, points the child Claude Code at it (HTTPS_PROXY=http://127.0.0.1:<port>,
// a URL with NO userinfo), plus the reclaude daemon's CA, and then execs the REAL
// `claude` binary, passing through all args.
//
// Why a local no-auth relay instead of HTTPS_PROXY=http://<key>@hub directly?  Because
// that is EXACTLY what reclaude does, and it is the reason reclaude is runtime-agnostic
// (works on both Bun- and Node-based Claude Code). The official Claude Code installed
// from claude.ai runs on Bun, and Bun's fetch CANNOT use a proxy URL that carries
// authentication userinfo (`http://key@host`) — it silently fails to open the socket and
// never sends CONNECT. A bare `http://127.0.0.1:<port>` has no userinfo, so every runtime
// honours it. The virtual-key auth is added by THIS relay when it dials the Hub, never
// exposed in the child's environment.
//
// Downstream→Hub transport: the relay opens a wss:// WebSocket to RECAUTH's /tunnel
// endpoint (443, through the Cloudflare Tunnel) carrying the sk-ra key + the CONNECT
// target in headers. RECAUTH chains a CONNECT to the real reclaude daemon and splices.
// Using 443/wss avoids needing a custom inbound port opened in the cloud firewall and
// mirrors how reclaude itself reaches its gateway (HTTPS to the edge).
//
// Chain:  claude → (local no-auth relay, this exe) → wss RECAUTH(hub, sk-ra auth) →
//         real reclaude daemon (signs + HPKE) → 网关.
//
// We NEVER touch the request: the real Claude Code generates the genuine request
// (genuine TLS fingerprint terminated by the daemon's MITM CA), and every hop only
// splices opaque bytes. This is the authoritative `claude + reclaude` combo with RECAUTH
// inserted at the connection layer for virtual-key auth + accounting.
//
// This is a self-contained Go module (its own go.mod) — build from this directory with `.`.
// Build (CGO_ENABLED=0, no cgo on any target):
//
//	GOOS=windows GOARCH=amd64 go build -o dist/recauth-launch.exe          .
//	GOOS=darwin  GOARCH=arm64 go build -o dist/recauth-launch-mac-arm64    .  # Apple Silicon
//	GOOS=darwin  GOARCH=amd64 go build -o dist/recauth-launch-mac-x64      .  # Intel Mac
//
// macOS double-click: ship dist/RECAUTH-启动.command (a bash wrapper that opens Terminal, de-
// quarantines, picks the arch). Platform-specific bits are switched at runtime by runtime.GOOS:
// the folder picker (PowerShell FolderBrowserDialog vs osascript `choose folder`), persistent
// env-var cleanup (HKCU\Environment vs commenting shell rc exports), and openBrowser.
//
// Override the baked-in endpoint/key at runtime with env RECAUTH_WS_URL / RECAUTH_KEY.
package main

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

//go:embed ca.pem
var caPEM []byte

// Baked default RECAUTH WebSocket endpoint. Override via RECAUTH_WS_URL.
const (
	defaultWSURL = "wss://recauth.timefiles.online/tunnel"
	// defaultPlaceholderToken is the FAKE OAuth access token planted in the downstream's
	// .credentials.json. It never reaches Anthropic: the reclaude daemon on the Hub MITMs
	// api.anthropic.com and substitutes acct1's genuine credentials. We deliberately do NOT
	// hand the downstream a real token (a leaked real token could be used directly against
	// api.anthropic.com, bypassing reclaude → account ban).
	//
	// Why a planted .credentials.json instead of CLAUDE_CODE_OAUTH_TOKEN env? Because the
	// env var yields an INFERENCE-ONLY scope (hardcoded in Claude Code's getClaudeAIOAuthTokens),
	// which makes claude skip its OAuth bootstrap. That bootstrap is what establishes the
	// reclaude daemon/gateway session state ("checkId") — skip it and the gateway returns
	// "400 reclaude state mismatch". A full-scope credentials file puts claude in full
	// subscriber mode so it runs the bootstrap, the session initializes, and requests flow.
	// (Verified against Claude Code source + live daemon.) Override token via RECAUTH_OAUTH_TOKEN.
	defaultPlaceholderToken = "recauth-tenant-placeholder"
)

// claudeAIOAuthScopes are the full Claude.ai subscriber scopes (from Claude Code's
// constants/oauth.ts CLAUDE_AI_OAUTH_SCOPES). The full set (notably user:profile) is what
// makes claude run the bootstrap that initializes the reclaude session.
var claudeAIOAuthScopes = []string{
	"user:profile",
	"user:inference",
	"user:sessions:claude_code",
	"user:mcp_servers",
	"user:file_upload",
}

const (
	hubDialTimeout = 20 * time.Second
	wsReadLimit    = 32 << 20
	wsPingInterval = 30 * time.Second
)

func main() {
	wsURL := getenvOr("RECAUTH_WS_URL", defaultWSURL)
	placeholderToken := getenvOr("RECAUTH_OAUTH_TOKEN", defaultPlaceholderToken)

	// `recauth-launch --recauth-login` forces a fresh device binding (re-bind / switch account).
	// The flag is consumed here so it is NOT forwarded to claude.
	childArgs, forceLogin := splitLoginFlag(os.Args[1:])
	// Double-click / no-arg launch = interactive mode: bind, then pick a project folder, then
	// run claude there. Pause on a fatal error so the console window doesn't vanish instantly.
	interactive = len(childArgs) == 0

	// The ONLY downstream credential is a per-device token obtained by binding this machine to a
	// user account (open the Hub portal, log in, click bind). It is saved locally and reused.
	key, err := resolveKey(wsURL, forceLogin)
	if err != nil {
		die("device binding failed: %v", err)
	}

	// Offer to clear any non-Anthropic endpoint/key left in the Claude Code environment so the
	// real Claude Code can't bypass RECAUTH to a third party (confirmed; only if detected).
	cleanClaudeEnv()

	// CA the child must trust (NODE_EXTRA_CA_CERTS). Prefer the LIVE bundle from RECAUTH
	// (covers every account in the pool, so an account add/replace never breaks downstream
	// TLS); fall back to the embedded single CA if the fetch fails.
	caPath := filepath.Join(os.TempDir(), "recauth-daemon-ca.pem")
	ca := caPEM
	if fetched, err := fetchCABundle(wsURL, key); err == nil && len(fetched) > 0 {
		ca = fetched
	}
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		die("write CA file: %v", err)
	}

	// Plant a full-scope placeholder login so claude runs in subscriber mode (and does the
	// bootstrap that initializes the reclaude session). Isolated config dir → never touches
	// the user's real ~/.claude, and never carries a real credential.
	configDir := filepath.Join(os.TempDir(), "recauth-claude-config")
	if err := writePlaceholderLogin(configDir, placeholderToken); err != nil {
		die("write placeholder login: %v", err)
	}

	// Route the relay's own logs to a file — in interactive mode the child claude owns the
	// terminal (a TUI), and any [relay] line on stderr would corrupt/overwrite the screen.
	if lf, err := os.OpenFile(filepath.Join(configDir, "recauth-relay.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		log.SetOutput(lf)
	} else {
		log.SetOutput(io.Discard)
	}

	claudePath, err := findOrInstallClaude()
	if err != nil {
		die("%v", err)
	}

	// Start the local no-auth relay and learn the port it bound to.
	localAddr, err := startLocalRelay(wsURL, key)
	if err != nil {
		die("start local relay: %v", err)
	}

	// The child sees a bare, auth-free proxy URL (Bun- and Node-safe).
	proxy := "http://" + localAddr
	env := filteredEnv()
	env = append(env,
		"HTTPS_PROXY="+proxy, "https_proxy="+proxy,
		"HTTP_PROXY="+proxy, "http_proxy="+proxy,
		// Don't proxy localhost (mirrors reclaude's own spawn env).
		"NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1",
		"NODE_EXTRA_CA_CERTS="+caPath,
		// Isolated config home holding the full-scope placeholder login (see writePlaceholderLogin).
		"CLAUDE_CONFIG_DIR="+configDir,
	)

	// In double-click mode, after auth let the user pick the project folder to work in.
	workDir := ""
	if interactive {
		fmt.Fprintln(os.Stderr, "请选择工程目录（claude 将以此为工作目录）…")
		workDir = pickFolder()
		if workDir != "" {
			// Validate before using it as cmd.Dir — a non-existent dir would make claude fail to start
			// with a chdir error. Fall back to the current dir so the launch still succeeds.
			if fi, err := os.Stat(workDir); err != nil || !fi.IsDir() {
				fmt.Fprintf(os.Stderr, "警告：工程目录无效（%s），改用当前目录。\n", workDir)
				workDir = ""
			} else {
				fmt.Fprintf(os.Stderr, "工程目录：%s\n", workDir)
			}
		}
	}

	// Goes to the relay log file, not stderr (keeps the interactive TUI clean).
	log.Printf("[recauth-launch] local relay %s -> hub %s ; launching %s (dir=%q)", localAddr, wsURL, claudePath, workDir)
	cmd := exec.Command(claudePath, childArgs...)
	cmd.Env = env
	cmd.Dir = workDir // "" = inherit current dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		die("run claude: %v", err)
	}
}

// startLocalRelay binds a no-auth CONNECT proxy on 127.0.0.1 and returns its "host:port".
// Each accepted CONNECT is carried to the Hub over a wss:// tunnel WITH the virtual key.
func startLocalRelay(wsURL, key string) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go relayConn(c, wsURL, key)
		}
	}()
	return ln.Addr().String(), nil
}

// relayConn reads one CONNECT from the local child, opens a wss tunnel to the Hub for that
// target, and splices the two streams verbatim.
func relayConn(client net.Conn, wsURL, key string) {
	defer client.Close()
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(client, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
		log.Printf("[relay] reject non-CONNECT %s %s", req.Method, req.Host)
		return
	}
	target := req.Host // "api.anthropic.com:443"

	ws, err := dialHubWS(wsURL, key, target)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		log.Printf("[relay] dial hub %s failed: %v", wsURL, err)
		return
	}
	defer ws.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	log.Printf("[relay] tunnel up %s via %s", target, wsURL)
	sent, recv := spliceClose(client, br, ws, ws)
	log.Printf("[relay] tunnel closed %s (sent=%dB recv=%dB)", target, sent, recv)
}

// dialHubWS opens the wss tunnel to RECAUTH for target, authenticating with the sk-ra key.
// It returns a net.Conn over the WebSocket (binary messages) and keeps it alive with pings.
func dialHubWS(wsURL, key, target string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(context.Background(), hubDialTimeout)
	defer cancel()
	c, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization":    {"Bearer " + key},
			"X-Recauth-Target": {target},
		},
	})
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(wsReadLimit)
	go pingLoop(c)
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

// fetchCABundle GETs the daemon pool's MITM CA bundle from RECAUTH (key-gated), so the child
// trusts every account in the pool. Returns an error if unavailable (caller falls back to the
// embedded CA).
func fetchCABundle(wsURL, key string) ([]byte, error) {
	caURL, err := caURLFromWS(wsURL)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, caURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ca fetch: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(b), "BEGIN CERTIFICATE") {
		return nil, fmt.Errorf("ca fetch: not a PEM bundle")
	}
	return b, nil
}

// caURLFromWS turns the wss tunnel URL into the https /tunnel-ca URL.
func caURLFromWS(wsURL string) (string, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}
	u.Path = strings.TrimSuffix(u.Path, "/tunnel") + "/tunnel-ca"
	u.RawQuery = ""
	return u.String(), nil
}

// pingLoop keeps the wss tunnel alive across idle gaps (Cloudflare drops idle WebSockets).
// It exits when a ping fails, i.e. once the connection is gone.
func pingLoop(c *websocket.Conn) {
	t := time.NewTicker(wsPingInterval)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := c.Ping(ctx)
		cancel()
		if err != nil {
			return
		}
	}
}

// spliceClose copies bytes both ways between the downstream conn (downW writes, downR
// reads — usually the same conn) and the upstream conn (up writes, upR reads). When either
// direction ends it closes both conns so the peer copy unblocks. Returns bytes sent each
// way.
func spliceClose(downW net.Conn, downR io.Reader, up net.Conn, upR io.Reader) (toUp, toDown int64) {
	var once sync.Once
	closeBoth := func() { _ = up.Close(); _ = downW.Close() }
	done := make(chan struct{}, 2)
	go func() {
		toUp, _ = io.Copy(up, downR)
		once.Do(closeBoth)
		done <- struct{}{}
	}()
	go func() {
		toDown, _ = io.Copy(downW, upR)
		once.Do(closeBoth)
		done <- struct{}{}
	}()
	<-done
	<-done
	return
}

// writePlaceholderLogin sets up an isolated claude config home so the child claude runs as
// a logged-in subscriber WITHOUT any real credential and WITHOUT the first-run wizard:
//
//   - .credentials.json: a full-scope Claude.ai OAuth login with a PLACEHOLDER token. Full
//     scope → claude does the bootstrap that initializes the reclaude session (skipping it is
//     what caused "400 state mismatch"). The token is fake; the daemon substitutes acct1's
//     real credential upstream, so nothing usable lands on the downstream machine. Rewritten
//     atomically each launch.
//   - .claude.json (global config): theme + hasCompletedOnboarding so the interactive
//     onboarding (which includes the OAuth-vs-APIkey login picker) is skipped entirely. Only
//     created if absent, so claude's own writes — notably the per-project trust acceptance —
//     persist across launches.
func writePlaceholderLogin(configDir, token string) error {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return err
	}
	// 1. credentials (always refreshed, written atomically to survive concurrent launches).
	type oauth struct {
		AccessToken      string   `json:"accessToken"`
		RefreshToken     string   `json:"refreshToken"`
		ExpiresAt        int64    `json:"expiresAt"`
		Scopes           []string `json:"scopes"`
		SubscriptionType string   `json:"subscriptionType"`
		RateLimitTier    *string  `json:"rateLimitTier"`
	}
	creds := map[string]oauth{
		"claudeAiOauth": {
			AccessToken:  token,
			RefreshToken: token + "-refresh",
			// Far future (year 2100, ms) so claude never tries to refresh the fake token.
			ExpiresAt:        4102444800000,
			Scopes:           claudeAIOAuthScopes,
			SubscriptionType: "max",
			RateLimitTier:    nil,
		},
	}
	b, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(configDir, ".credentials.json"), b); err != nil {
		return err
	}
	// 2. global config — RESET the session-bearing state EVERY launch so claude re-runs its
	// login bootstrap. This faithfully replicates reclaude's invariant that每一次启动 claude
	// 都要"走一遍"才能进入 session: claude only calls /api/oauth/profile (and the startup
	// requests that make the reclaude daemon establish THIS launch's gateway session) when it
	// is NOT already logged-in-with-a-cached-account. If we preserve claude's cached
	// `oauthAccount` across launches, a later launch skips that bootstrap, the gateway session
	// for this launch is never initialized, and the gateway returns "400 reclaude state
	// mismatch" (verified: oauthAccount is populated by /api/oauth/profile during login —
	// Claude Code src bridge/bridgeEnabled.ts). So every launch we rebuild .claude.json to a
	// fresh-but-onboarded config, carrying over ONLY the per-project trust map (projects[],
	// holding hasTrustDialogAccepted) so the user isn't re-prompted to trust the folder.
	gc := filepath.Join(configDir, ".claude.json")
	prev := map[string]any{}
	if b, err := os.ReadFile(gc); err == nil {
		_ = json.Unmarshal(b, &prev) // tolerate empty/corrupt: fall back to {}
	}
	fresh := map[string]any{
		"theme":                  pickString(prev["theme"], "dark"), // keep a theme the user picked
		"hasCompletedOnboarding": true,                              // skip the OAuth/API-key picker
	}
	if projects, ok := prev["projects"]; ok {
		fresh["projects"] = projects // preserve folder-trust acceptance
	}
	out, err := json.Marshal(fresh)
	if err != nil {
		return err
	}
	return atomicWrite(gc, out)
}

// pickString returns v as a string if it is a non-empty string, else def.
func pickString(v any, def string) string {
	if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
		return s
	}
	return def
}

// atomicWrite writes via a temp file + rename so a concurrent reader never sees a partial
// file (multiple launcher instances may share one config dir).
func atomicWrite(path string, data []byte) error {
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// findRealClaude locates the genuine claude executable on PATH, refusing to pick this
// launcher itself (in case it was renamed to "claude").
func findRealClaude() (string, error) {
	self, _ := os.Executable()
	selfBase := strings.ToLower(filepath.Base(self))
	p, err := exec.LookPath("claude")
	if err != nil {
		return "", fmt.Errorf("claude not found on PATH")
	}
	if strings.EqualFold(filepath.Base(p), selfBase) {
		return "", fmt.Errorf("PATH 'claude' resolves to this launcher; install the real Claude Code")
	}
	return p, nil
}

// filteredEnv returns the current environment minus the vars we set ourselves and
// ANTHROPIC_BASE_URL (claude must talk to the default api.anthropic.com so the proxy
// intercepts it; a custom base URL would bypass the tunnel).
func filteredEnv() []string {
	drop := map[string]bool{
		"HTTPS_PROXY": true, "HTTP_PROXY": true, "https_proxy": true, "http_proxy": true,
		"NO_PROXY": true, "no_proxy": true,
		"NODE_EXTRA_CA_CERTS": true, "ANTHROPIC_BASE_URL": true, "CLAUDE_CONFIG_DIR": true,
		// We own auth via the planted full-scope credentials.json. Drop every other credential
		// source so none overrides it: ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN would disable
		// OAuth (no oauth marker); CLAUDE_CODE_OAUTH_TOKEN would force inference-only scope
		// (skips bootstrap → "state mismatch").
		"ANTHROPIC_API_KEY": true, "ANTHROPIC_AUTH_TOKEN": true, "CLAUDE_CODE_OAUTH_TOKEN": true,
	}
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if drop[k] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// --- device binding (activation) ---

type storedConfig struct {
	Key string `json:"key"`
}

// splitLoginFlag pulls --recauth-login out of the args (so it isn't forwarded to claude) and
// reports whether it was present.
func splitLoginFlag(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	force := false
	for _, a := range args {
		if a == "--recauth-login" {
			force = true
			continue
		}
		out = append(out, a)
	}
	return out, force
}

// resolveKey returns the device token to use: the stored token, else it runs the interactive
// device-binding flow and persists the resulting token.
func resolveKey(wsURL string, forceLogin bool) (string, error) {
	cfg := configFilePath()
	if !forceLogin {
		if k := readStoredKey(cfg); k != "" {
			return k, nil
		}
	}
	tok, err := activateDevice(wsURL)
	if err != nil {
		return "", err
	}
	if err := saveStoredKey(cfg, tok); err != nil {
		fmt.Fprintf(os.Stderr, "recauth-launch: 警告：保存凭证失败（下次需重新绑定）：%v\n", err)
	}
	return tok, nil
}

// activateDevice runs the Hub device-binding flow: start → open the /activate page → poll until
// the operator pastes the sk and the device token is issued.
func activateDevice(wsURL string) (string, error) {
	base, err := activateBaseFromWS(wsURL)
	if err != nil {
		return "", err
	}
	host, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{"hostname": host, "os": runtime.GOOS, "arch": runtime.GOARCH})
	var start struct {
		Code         string `json:"code"`
		ActivateURL  string `json:"activateUrl"`
		PollInterval int    `json:"pollInterval"`
	}
	if err := postJSON(base+"/api/activate/start", body, &start); err != nil {
		return "", fmt.Errorf("start: %w", err)
	}
	if start.Code == "" || start.ActivateURL == "" {
		return "", fmt.Errorf("start: 响应不完整")
	}
	fmt.Fprintf(os.Stderr, "\n== RECAUTH 设备绑定 ==\n在浏览器打开下面的链接，粘贴你的 sk-ra- 密钥以授权本机：\n\n  %s\n\n等待网页端绑定…\n", start.ActivateURL)
	openBrowser(start.ActivateURL)

	interval := time.Duration(start.PollInterval) * time.Second
	if interval < 3*time.Second {
		interval = 3 * time.Second
	}
	deadline := time.Now().Add(10 * time.Minute)
	pollBody, _ := json.Marshal(map[string]string{"code": start.Code})
	for time.Now().Before(deadline) {
		time.Sleep(interval)
		var poll struct {
			Status string `json:"status"`
			Token  string `json:"token"`
		}
		if err := postJSON(base+"/api/activate/poll", pollBody, &poll); err != nil {
			continue // transient; keep polling
		}
		switch poll.Status {
		case "approved":
			if poll.Token == "" {
				return "", fmt.Errorf("已批准但未返回设备 token")
			}
			fmt.Fprintln(os.Stderr, "绑定成功。")
			return poll.Token, nil
		case "expired":
			return "", fmt.Errorf("激活码已过期，请重试")
		}
	}
	return "", fmt.Errorf("等待绑定超时")
}

// postJSON POSTs body to url and decodes a JSON response into out.
func postJSON(url string, body []byte, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// activateBaseFromWS turns the wss tunnel URL into the https origin (scheme + host, no path).
func activateBaseFromWS(wsURL string) (string, error) {
	u, err := url.Parse(wsURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}
	return u.Scheme + "://" + u.Host, nil
}

func configFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		home = os.TempDir()
	}
	return filepath.Join(home, ".recauth", "config.json")
}

func readStoredKey(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var c storedConfig
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	return strings.TrimSpace(c.Key)
}

func saveStoredKey(path, key string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(storedConfig{Key: key})
	return os.WriteFile(path, b, 0o600)
}

// interactive is true for a no-arg (double-click) launch: pick a folder + pause on error.
var interactive bool

// pickFolder shows a native folder picker and returns the chosen path ("" if cancelled or
// unsupported). Windows uses a WinForms FolderBrowserDialog via PowerShell (no cgo); macOS
// uses an AppleScript `choose folder` via osascript; other OSes fall back to the current dir.
func pickFolder() string {
	switch runtime.GOOS {
	case "windows":
		// Force UTF-8 output and wrap the path in markers so we can extract it byte-exactly. On a
		// Chinese Windows the console code page (GBK/936) otherwise mangles non-ASCII folder names
		// and can leave trailing buffer garbage on the captured path (e.g. "D:\Desktop\claude   Ѫ"),
		// which then fails chdir. Markers + UTF-8 make the capture immune to code page / BOM noise.
		ps := "[Console]::OutputEncoding = (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false); " +
			"Add-Type -AssemblyName System.Windows.Forms; " +
			"$f = New-Object System.Windows.Forms.FolderBrowserDialog; " +
			"$f.Description = '选择工程目录（claude 将以此为工作目录）'; " +
			"$f.ShowNewFolderButton = $true; " +
			"if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Out.Write('<RECAUTHPATH>' + $f.SelectedPath + '</RECAUTHPATH>') }"
		out, err := exec.Command("powershell", "-NoProfile", "-STA", "-Command", ps).Output()
		if err != nil {
			return ""
		}
		return pathBetween(string(out), "<RECAUTHPATH>", "</RECAUTHPATH>")
	case "darwin":
		// `choose folder` returns an alias; `POSIX path of` yields a real /path/. A user
		// cancel makes osascript exit non-zero (treated as "" = no selection).
		script := `try
	set p to POSIX path of (choose folder with prompt "选择工程目录（claude 将以此为工作目录）")
	return p
end try`
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	default:
		return ""
	}
}

// pathBetween returns the substring between the first `open` marker and the next `close` marker,
// trimmed. Used to extract the picked folder path byte-exactly from the PowerShell output, ignoring
// any BOM, code-page padding, or console buffer garbage that may surround it. Returns "" if either
// marker is missing.
func pathBetween(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

// openBrowser best-effort opens a URL in the default browser.
func openBrowser(u string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		c = exec.Command("open", u)
	default:
		c = exec.Command("xdg-open", u)
	}
	_ = c.Start()
}

func getenvOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "recauth-launch: "+format+"\n", a...)
	if interactive {
		// Double-click mode: keep the console open so the user can read the error.
		fmt.Fprint(os.Stderr, "\n按回车键退出…")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(1)
}
