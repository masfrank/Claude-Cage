package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// nonStringControlURLMarker is snapshot control_url when settings.json has JSON
// null or a non-string. Decoding those into a string would yield "" and look
// like the official service; this marker is not a valid URL, so the host sees
// mismatch until useControlURL writes a real string.
const nonStringControlURLMarker = "invalid"

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

func (n *node) loadSettings(b []byte) error {
	var file struct {
		Enabled    bool            `json:"enabled"`
		Keys       []string        `json:"keys"`
		ControlURL json.RawMessage `json:"control_url"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		return err
	}
	n.config.Enabled = file.Enabled
	n.config.Keys = file.Keys
	n.applyPersistedControlURL(file.ControlURL)
	return nil
}

func (n *node) applyPersistedControlURL(raw json.RawMessage) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return
	}
	if bytes.Equal(raw, []byte("null")) {
		n.markInvalidPersistedControlURL(nonStringControlURLMarker)
		return
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		n.markInvalidPersistedControlURL(nonStringControlURLMarker)
		return
	}
	if text == "" {
		return
	}
	normalized, err := normalizeControlURL(text)
	if err != nil {
		n.markInvalidPersistedControlURL(text)
		return
	}
	n.config.ControlURL = normalized
}

func (n *node) markInvalidPersistedControlURL(reported string) {
	n.config.ControlURL = reported
	n.invalidControl = true
	n.startError = invalidPersistedControlURL
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
