package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

const invalidPersistedControlURL = "已保存的控制服务器地址无效，请在 Tailscale 面板重新保存控制服务器"

func inheritedTailnetEnv() []string {
	return []string{"TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET", "TS_CLIENT_ID", "TSNET_FORCE_LOGIN", "TS_CONTROL_URL"}
}

func clearInheritedTailnetEnv() {
	for _, key := range inheritedTailnetEnv() {
		_ = os.Unsetenv(key)
	}
}

func invalidControlURL() error {
	return errors.New("控制服务器地址须为 HTTPS 地址，只包含主机和可选端口，例如 https://headscale.example.com")
}

func normalizeControlURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if len(raw) > 1024 {
		return "", invalidControlURL()
	}
	for _, r := range trimmed {
		if r < 0x20 || r == 0x7f || r == '\\' || unicode.IsSpace(r) {
			return "", invalidControlURL()
		}
	}
	if strings.ContainsAny(trimmed, "?#%") {
		return "", invalidControlURL()
	}
	u, err := url.Parse(trimmed)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Opaque != "" || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return "", invalidControlURL()
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "%") {
		return "", invalidControlURL()
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || port != strconv.Itoa(n) {
			return "", invalidControlURL()
		}
		if n == 443 {
			port = ""
		}
	}
	host = strings.ToLower(host)
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	out := "https://" + host
	if port != "" {
		out += ":" + port
	}
	if out == "https://controlplane.tailscale.com" || out == "https://login.tailscale.com" {
		return "", nil
	}
	return out, nil
}

func (n *node) stateDir() string {
	if n.config.ControlURL == "" {
		return n.dir
	}
	sum := sha256.Sum256([]byte(n.config.ControlURL))
	return filepath.Join(n.dir, "servers", hex.EncodeToString(sum[:]))
}

func (n *node) applyPersistedControlURL() {
	if n.config.ControlURL == "" {
		return
	}
	normalized, err := normalizeControlURL(n.config.ControlURL)
	if err != nil {
		n.invalidControl = true
		n.startError = invalidPersistedControlURL
		return
	}
	n.config.ControlURL = normalized
}

func (n *node) useControlURL(raw string) error {
	next, err := normalizeControlURL(raw)
	if err != nil {
		return err
	}
	return n.switchControlURL(next)
}

func (n *node) switchControlURL(next string) error {
	if n.config.ControlURL == next && !n.invalidControl {
		return nil
	}
	wasRunning := n.server != nil
	n.stop()
	_ = n.writeSSHConfig(nil)
	prev := n.config.ControlURL
	prevInvalid := n.invalidControl
	n.config.ControlURL = next
	n.invalidControl = false
	if err := n.save(); err != nil {
		n.config.ControlURL = prev
		n.invalidControl = prevInvalid
		if wasRunning {
			_ = n.start()
		}
		return err
	}
	if !n.config.Enabled {
		n.startError = ""
		return nil
	}
	_ = n.start()
	return nil
}
