// cleanup.go — two pre-launch safeguards for the downstream machine:
//
//  1. cleanClaudeEnv: detect non-Anthropic API endpoints/keys left in the Claude Code
//     environment (persistent env vars + ~/.claude/settings.json) and, with confirmation,
//     remove them. A stray custom base URL or API key would route the user's real Claude Code
//     to a third party (bypassing RECAUTH) — risky and confusing — so we offer to clear it.
//
//  2. findOrInstallClaude: if Claude Code isn't installed, offer to install it from the
//     npmmirror (Taobao) registry, which is reliable from CN networks.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// envKeys are the Claude Code credential/endpoint env vars we treat as "should not be set" on a
// RECAUTH machine (RECAUTH plants its own isolated login). ANTHROPIC_BASE_URL is only flagged
// when it points somewhere other than anthropic.com.
var anthropicEnvKeys = []string{
	"ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
}

type envHit struct {
	source string // "环境变量" | "settings.json"
	name   string
	value  string
}

// cleanClaudeEnv scans for non-Anthropic endpoints/keys and, if any are found, asks to remove them.
func cleanClaudeEnv() {
	hits := detectEnvLeftovers()
	if len(hits) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr, "\n检测到 Claude Code 环境中存在非 Anthropic 的端点/密钥：")
	for _, h := range hits {
		fmt.Fprintf(os.Stderr, "  - [%s] %s = %s\n", h.source, h.name, maskVal(h.value))
	}
	fmt.Fprintln(os.Stderr, "这些会让 Claude Code 绕过 RECAUTH 直连第三方（有风险）。")
	if !confirmYN("是否清理它们?") {
		fmt.Fprintln(os.Stderr, "已跳过清理。")
		return
	}
	cleanEnvHits(hits)
}

func detectEnvLeftovers() []envHit {
	var hits []envHit
	for _, n := range anthropicEnvKeys {
		v := strings.TrimSpace(os.Getenv(n))
		if v == "" {
			continue
		}
		if n == "ANTHROPIC_BASE_URL" && isAnthropicURL(v) {
			continue // pointing at Anthropic itself is fine
		}
		hits = append(hits, envHit{source: "环境变量", name: n, value: v})
	}
	// ~/.claude/settings.json env block.
	for _, n := range settingsEnvKeys() {
		hits = append(hits, envHit{source: "settings.json", name: n.name, value: n.value})
	}
	return hits
}

type kv struct{ name, value string }

func settingsEnvKeys() []kv {
	path := settingsJSONPath()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	env, _ := doc["env"].(map[string]any)
	if env == nil {
		return nil
	}
	var out []kv
	for _, n := range anthropicEnvKeys {
		v, ok := env[n].(string)
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		if n == "ANTHROPIC_BASE_URL" && isAnthropicURL(v) {
			continue
		}
		out = append(out, kv{name: n, value: v})
	}
	return out
}

func cleanEnvHits(hits []envHit) {
	editSettings := false
	for _, h := range hits {
		switch h.source {
		case "环境变量":
			_ = os.Unsetenv(h.name) // this process
			removePersistentEnvVar(h.name)
		case "settings.json":
			editSettings = true
		}
	}
	if editSettings {
		removeSettingsEnv()
	}
}

// removePersistentEnvVar deletes a persistent env var so future sessions don't re-inherit it.
// Windows: the User-scope registry value. macOS/Linux: comment out the export line in the
// user's shell rc files (env vars there have no central store).
func removePersistentEnvVar(name string) {
	if runtime.GOOS == "windows" {
		_ = exec.Command("reg", "delete", `HKCU\Environment`, "/v", name, "/f").Run()
		fmt.Fprintf(os.Stderr, "  已移除用户环境变量 %s\n", name)
		return
	}
	if n := removeUnixEnvExport(name); n == 0 {
		fmt.Fprintf(os.Stderr, "  已在本进程取消 %s（未在 shell 配置中找到声明；若仍存在请手动删除该行）\n", name)
	}
}

// removeUnixEnvExport scans the common shell rc files and comments out any line that exports
// `name` (so it survives review and can be undone). Returns how many lines were commented.
func removeUnixEnvExport(name string) int {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return 0
	}
	rcFiles := []string{".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile"}
	total := 0
	for _, f := range rcFiles {
		path := filepath.Join(home, f)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(b), "\n")
		changed := false
		for i, ln := range lines {
			t := strings.TrimSpace(ln)
			if strings.HasPrefix(t, "#") {
				continue
			}
			if strings.HasPrefix(t, "export "+name+"=") || strings.HasPrefix(t, name+"=") {
				lines[i] = "# [recauth-launch 已注释] " + ln
				changed = true
				total++
			}
		}
		if changed {
			if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), info.Mode().Perm()); err == nil {
				fmt.Fprintf(os.Stderr, "  已在 %s 注释掉 %s 的声明\n", path, name)
			}
		}
	}
	return total
}

func removeSettingsEnv() {
	path := settingsJSONPath()
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return
	}
	env, _ := doc["env"].(map[string]any)
	if env == nil {
		return
	}
	for _, n := range anthropicEnvKeys {
		if v, ok := env[n].(string); ok && !(n == "ANTHROPIC_BASE_URL" && isAnthropicURL(v)) {
			delete(env, n)
		}
	}
	doc["env"] = env
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(path, out, 0o600); err == nil {
		fmt.Fprintf(os.Stderr, "  已清理 %s 中的非 Anthropic env 项\n", path)
	}
}

func settingsJSONPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", "settings.json")
}

func isAnthropicURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "anthropic.com" || strings.HasSuffix(host, ".anthropic.com")
}

func maskVal(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 10 {
		return v
	}
	return v[:6] + "…" + v[len(v)-2:]
}

// findOrInstallClaude locates Claude Code, offering to install it via npmmirror when absent.
func findOrInstallClaude() (string, error) {
	if p, err := findRealClaude(); err == nil {
		return p, nil
	}
	fmt.Fprintln(os.Stderr, "\n未检测到 Claude Code (claude)。")
	if !confirmYN("是否现在用淘宝镜像(npmmirror)安装 Claude Code?") {
		return "", fmt.Errorf("需要先安装 Claude Code：npm i -g @anthropic-ai/claude-code")
	}
	if _, err := exec.LookPath("npm"); err != nil {
		return "", fmt.Errorf("未检测到 npm，请先安装 Node.js (https://nodejs.org) 后重试")
	}
	fmt.Fprintln(os.Stderr, "正在安装 @anthropic-ai/claude-code（registry: npmmirror）…")
	c := exec.Command("npm", "install", "-g", "@anthropic-ai/claude-code", "--registry", "https://registry.npmmirror.com")
	c.Stdout, c.Stderr, c.Stdin = os.Stderr, os.Stderr, os.Stdin
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("安装失败：%v", err)
	}
	fmt.Fprintln(os.Stderr, "安装完成。")
	return findRealClaude()
}

// confirmYN reads a y/N answer from stdin (default No).
func confirmYN(q string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", q)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}
