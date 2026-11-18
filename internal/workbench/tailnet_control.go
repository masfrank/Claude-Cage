package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	bridgeNotInstalled = "notInstalled"
	bridgeSupported    = "supported"
	bridgeLegacy       = "legacy"
	bridgeStranded     = "stranded"

	tailnetControlInvalid     = "tailnet-control-invalid"
	tailnetControlUnsupported = "tailnet-control-unsupported"
	tailnetControlPending     = "tailnet-control-pending"
	tailnetControlRestored    = "tailnet-control-restored"
	tailnetControlUnreadable  = "tailnet-control-unreadable"
	tailnetAuthURLInvalid     = "tailnet-auth-url-invalid"
)

var errTailnetUnreadable = errors.New("Tailscale 控制服务器设置无法读取，请在 Tailscale 面板重新保存控制服务器")

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

func validCustomTailnetAuthURL(raw, desired string) bool {
	if raw == "" || len(raw) > 8192 || strings.Contains(raw, `\`) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Hostname() == "" {
		return false
	}
	d, err := url.Parse(desired)
	if err != nil || d.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(u.Hostname(), d.Hostname()) {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	want := d.Port()
	if want == "" {
		want = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || port != strconv.Itoa(n) {
		return false
	}
	return port == want
}

func tailnetControlError(w http.ResponseWriter, status int, recovery, message string) {
	w.Header().Set("X-Cage-Recovery", recovery)
	http.Error(w, message, status)
}

func unsupportedControlMessage(desired string) string {
	if desired == "" {
		return "当前环境组件无法切换控制服务器。请在设置中更新环境组件。"
	}
	return "当前环境组件不支持自建控制服务器。请在设置中更新环境组件，或改用 Tailscale 官方服务。"
}

func parseControlServerInput(w http.ResponseWriter, raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		http.Error(w, "请求格式无效", 400)
		return "", false
	}
	var next string
	if json.Unmarshal(raw, &next) != nil {
		http.Error(w, "请求格式无效", 400)
		return "", false
	}
	normalized, err := normalizeControlURL(next)
	if err != nil {
		tailnetControlError(w, 400, tailnetControlInvalid, err.Error())
		return "", false
	}
	return normalized, true
}

func (s *Server) tailscalePath() string {
	return filepath.Join(s.profile, "tailscale.json")
}

func (s *Server) readDesiredControlURL() (string, error) {
	b, err := os.ReadFile(s.tailscalePath())
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '{' {
		return "", errTailnetUnreadable
	}
	var file struct {
		ControlURL json.RawMessage `json:"control_url"`
	}
	if json.Unmarshal(b, &file) != nil {
		return "", errTailnetUnreadable
	}
	raw := bytes.TrimSpace(file.ControlURL)
	if len(raw) == 0 {
		return "", nil
	}
	if bytes.Equal(raw, []byte("null")) {
		return "", errTailnetUnreadable
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return "", errTailnetUnreadable
	}
	next, err := normalizeControlURL(text)
	if err != nil {
		return "", errTailnetUnreadable
	}
	return next, nil
}

func (s *Server) writeDesiredControlURL(next string) error {
	return writePrivate(s.tailscalePath(), struct {
		ControlURL string `json:"control_url"`
	}{next})
}

func (s *Server) withTailnet(w http.ResponseWriter, takeOp bool, fn func(token string)) {
	if takeOp {
		if !s.op.TryLock() {
			http.Error(w, "环境正在执行其他操作，请稍后再试", http.StatusConflict)
			return
		}
		defer s.op.Unlock()
	}
	s.tailnetMu.Lock()
	defer s.tailnetMu.Unlock()
	s.mu.Lock()
	closing, ready, running, token := s.closing, s.ready, s.jobs.snapshot().Running, s.credentials.Token
	s.mu.Unlock()
	if closing || !ready || running {
		http.Error(w, "请先启动 Cage 环境，并等待当前操作完成", http.StatusConflict)
		return
	}
	fn(token)
}

func (s *Server) tailnetGuest(parent context.Context, token string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	return s.guestAPI(ctx, token, http.MethodPost, "/tailnet", raw)
}

func decodeTailnetState(data []byte) (map[string]json.RawMessage, error) {
	var result map[string]json.RawMessage
	if json.Unmarshal(data, &result) != nil || result == nil {
		return nil, errors.New("Tailscale 组件返回了无效状态")
	}
	return result, nil
}

func tailnetErrorMessage(result map[string]json.RawMessage) string {
	b := result["tailnet_error"]
	if len(b) == 0 {
		return ""
	}
	var reason string
	_ = json.Unmarshal(b, &reason)
	return reason
}

func classifyTailnetBridge(result map[string]json.RawMessage) (class, applied string) {
	var installed bool
	_ = json.Unmarshal(result["installed"], &installed)
	if !installed {
		return bridgeNotInstalled, ""
	}
	var caps []string
	_ = json.Unmarshal(result["capabilities"], &caps)
	_, has := result["control_url"]
	if has {
		_ = json.Unmarshal(result["control_url"], &applied)
	}
	supported := false
	for _, cap := range caps {
		if cap == "control-url" {
			supported = true
			break
		}
	}
	if supported {
		return bridgeSupported, applied
	}
	if !has {
		return bridgeLegacy, ""
	}
	return bridgeStranded, applied
}

func deriveControlURLStatus(class, desired, applied string) string {
	switch class {
	case bridgeNotInstalled:
		return "ok"
	case bridgeSupported:
		if applied == desired {
			return "ok"
		}
		return "mismatch"
	case bridgeLegacy:
		if desired == "" {
			return "ok"
		}
		return "unsupported"
	case bridgeStranded:
		if applied == desired {
			return "ok"
		}
		return "unsupported"
	default:
		return "unsupported"
	}
}

func jsonRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func shapeTailnetState(result map[string]json.RawMessage, desired, class, applied string) map[string]json.RawMessage {
	status := deriveControlURLStatus(class, desired, applied)
	if status != "ok" {
		delete(result, "auth_url")
		delete(result, "proxy_url")
		result["peers"] = json.RawMessage("[]")
		result["forwards"] = json.RawMessage("[]")
		result["ips"] = json.RawMessage("[]")
		for _, key := range []string{"tailnet", "account", "name", "hostname", "os", "return_id"} {
			delete(result, key)
		}
	}
	result["control_url"] = jsonRaw(desired)
	result["control_url_status"] = jsonRaw(status)
	if class == bridgeSupported {
		result["control_url_applied"] = jsonRaw(applied)
	} else {
		delete(result, "control_url_applied")
	}
	return result
}

func writeTailnetState(w http.ResponseWriter, result map[string]json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(result)
	_, _ = w.Write(b)
}

func (s *Server) finishTailnet(w http.ResponseWriter, data []byte, err error, desired string) {
	if err != nil {
		http.Error(w, "Tailscale 操作未完成。请更新环境组件后重试；原设备身份和 SSH 公钥会保留。", 502)
		return
	}
	result, err := decodeTailnetState(data)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	if reason := tailnetErrorMessage(result); reason != "" {
		http.Error(w, reason, 502)
		return
	}
	class, applied := classifyTailnetBridge(result)
	status := deriveControlURLStatus(class, desired, applied)
	var authURL string
	_ = json.Unmarshal(result["auth_url"], &authURL)
	if status == "ok" && authURL != "" {
		if desired == "" {
			if !validTailnetAuthURL(authURL) {
				http.Error(w, "Tailscale 登录地址无效，请重新发起登录", 502)
				return
			}
		} else if !validCustomTailnetAuthURL(authURL, desired) {
			tailnetControlError(w, 502, tailnetAuthURLInvalid, "Tailscale 登录地址无效，请重新发起登录")
			return
		}
	}
	writeTailnetState(w, shapeTailnetState(result, desired, class, applied))
}

func (s *Server) handleTailnetAction(w http.ResponseWriter, r *http.Request, action, key, host string, port int) {
	s.withTailnet(w, r.Method != http.MethodGet, func(token string) {
		desired, err := s.readDesiredControlURL()
		if err != nil {
			tailnetControlError(w, 500, tailnetControlUnreadable, errTailnetUnreadable.Error())
			return
		}
		if r.Method == http.MethodGet {
			data, err := s.tailnetGuest(r.Context(), token, map[string]string{"action": "status"})
			s.finishTailnet(w, data, err, desired)
			return
		}
		data, err := s.tailnetGuest(r.Context(), token, map[string]string{"action": "status"})
		if err != nil {
			http.Error(w, "Tailscale 操作未完成。请更新环境组件后重试；原设备身份和 SSH 公钥会保留。", 502)
			return
		}
		result, err := decodeTailnetState(data)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		if reason := tailnetErrorMessage(result); reason != "" {
			http.Error(w, reason, 502)
			return
		}
		class, applied := classifyTailnetBridge(result)
		send := map[string]any{"action": action}
		if key != "" {
			send["key"] = key
		}
		if action == "open-service" {
			send["host"] = host
			send["port"] = port
		}
		switch class {
		case bridgeNotInstalled:
		case bridgeSupported:
			send["control_url"] = desired
		case bridgeLegacy:
			if desired != "" {
				tailnetControlError(w, 409, tailnetControlUnsupported, unsupportedControlMessage(desired))
				return
			}
		case bridgeStranded:
			if applied != desired {
				tailnetControlError(w, 409, tailnetControlUnsupported, unsupportedControlMessage(desired))
				return
			}
		}
		data, err = s.tailnetGuest(r.Context(), token, send)
		s.finishTailnet(w, data, err, desired)
	})
}

func (s *Server) handleControlServer(w http.ResponseWriter, r *http.Request, next string) {
	s.withTailnet(w, true, func(token string) {
		prev, prevErr := s.readDesiredControlURL()
		data, err := s.tailnetGuest(r.Context(), token, map[string]string{"action": "status"})
		if err != nil {
			tailnetControlError(w, 502, tailnetControlPending, "控制服务器切换结果待核对，请再次保存以重试。")
			return
		}
		result, err := decodeTailnetState(data)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		if tailnetErrorMessage(result) != "" {
			tailnetControlError(w, 502, tailnetControlPending, "控制服务器切换结果待核对，请再次保存以重试。")
			return
		}
		class, applied := classifyTailnetBridge(result)
		switch class {
		case bridgeNotInstalled:
			if err := s.writeDesiredControlURL(next); err != nil {
				http.Error(w, "保存控制服务器失败，请重试", 500)
				return
			}
			writeTailnetState(w, shapeTailnetState(result, next, class, applied))
			return
		case bridgeLegacy:
			if next != "" {
				tailnetControlError(w, 409, tailnetControlUnsupported, unsupportedControlMessage(next))
				return
			}
			if err := s.writeDesiredControlURL(next); err != nil {
				http.Error(w, "保存控制服务器失败，请重试", 500)
				return
			}
			writeTailnetState(w, shapeTailnetState(result, next, class, applied))
			return
		case bridgeStranded:
			if next != applied {
				tailnetControlError(w, 409, tailnetControlUnsupported, unsupportedControlMessage(next))
				return
			}
			if err := s.writeDesiredControlURL(next); err != nil {
				http.Error(w, "保存控制服务器失败，请重试", 500)
				return
			}
			writeTailnetState(w, shapeTailnetState(result, next, class, applied))
			return
		}
		body := map[string]string{"action": "control-server", "control_url": next}
		data, err = s.tailnetGuest(r.Context(), token, body)
		if err != nil {
			tailnetControlError(w, 502, tailnetControlPending, "控制服务器切换结果待核对，请再次保存以重试。")
			return
		}
		result, err = decodeTailnetState(data)
		if err != nil || tailnetErrorMessage(result) != "" {
			tailnetControlError(w, 502, tailnetControlPending, "控制服务器切换结果待核对，请再次保存以重试。")
			return
		}
		_, applied = classifyTailnetBridge(result)
		if applied != next {
			tailnetControlError(w, 502, tailnetControlPending, "控制服务器切换结果待核对，请再次保存以重试。")
			return
		}
		if err := s.writeDesiredControlURL(next); err != nil {
			if prevErr != nil {
				tailnetControlError(w, 500, tailnetControlPending, "控制服务器切换结果待核对，请再次保存以重试。")
				return
			}
			ctx, cancel := context.WithTimeout(s.lifetimeContext(), 15*time.Second)
			defer cancel()
			comp, compErr := s.tailnetGuest(ctx, token, map[string]string{"action": "control-server", "control_url": prev})
			if compErr != nil {
				tailnetControlError(w, 500, tailnetControlPending, "控制服务器切换结果待核对，请再次保存以重试。")
				return
			}
			compState, decErr := decodeTailnetState(comp)
			if decErr != nil || tailnetErrorMessage(compState) != "" {
				tailnetControlError(w, 500, tailnetControlPending, "控制服务器切换结果待核对，请再次保存以重试。")
				return
			}
			_, compApplied := classifyTailnetBridge(compState)
			if compApplied != prev {
				tailnetControlError(w, 500, tailnetControlPending, "控制服务器切换结果待核对，请再次保存以重试。")
				return
			}
			tailnetControlError(w, 500, tailnetControlRestored, "保存控制服务器失败，已恢复原设置。")
			return
		}
		class, applied = classifyTailnetBridge(result)
		writeTailnetState(w, shapeTailnetState(result, next, class, applied))
	})
}
