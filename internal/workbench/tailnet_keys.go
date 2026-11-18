package workbench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

const hiddenTailnetKey = "[已隐藏]"

var (
	errInvalidTailnetState = errors.New("Tailscale 组件返回了无效状态")
	sshKeyFragmentPattern  = regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`)
)

type sshKeyMeta struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Comment string `json:"comment"`
}

func parseTailnetKeyLine(line string) (id, keyType, comment string, valid bool) {
	key, parsedComment, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(options) != 0 || strings.TrimSpace(string(rest)) != "" {
		sum := sha256.Sum256([]byte(line))
		return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), "unknown", "", false
	}
	return ssh.FingerprintSHA256(key), key.Type(), sanitizeTailnetKeyComment(parsedComment), true
}

func sanitizeTailnetKeyComment(comment string) string {
	var b strings.Builder
	for _, r := range comment {
		if !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	cleaned := b.String()
	if sshKeyFragmentPattern.MatchString(cleaned) {
		return ""
	}
	runes := []rune(cleaned)
	if len(runes) > 128 {
		return string(runes[:128])
	}
	return cleaned
}

func scrubTailnetText(s string) string {
	return sshKeyFragmentPattern.ReplaceAllString(s, hiddenTailnetKey)
}

func decodeTailnetKeyLines(result map[string]json.RawMessage) ([]string, error) {
	raw, ok := result["keys"]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return []string{}, nil
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, errInvalidTailnetState
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		item = bytes.TrimSpace(item)
		if len(item) == 0 || item[0] != '"' {
			return nil, errInvalidTailnetState
		}
		var line string
		if json.Unmarshal(item, &line) != nil {
			return nil, errInvalidTailnetState
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func matchingTailnetKeyLines(lines []string, id string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		parsedID, _, _, _ := parseTailnetKeyLine(line)
		if parsedID == id {
			out = append(out, line)
		}
	}
	return out
}

func uniqueTailnetKeyLines(lines []string) []string {
	seen := make(map[string]bool, len(lines))
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}

func collectTailnetKeyMaterial(lines []string) []string {
	seen := make(map[string]bool)
	var known []string
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		known = append(known, s)
	}
	for _, line := range lines {
		key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err == nil && len(options) == 0 && strings.TrimSpace(string(rest)) == "" {
			add(base64.StdEncoding.EncodeToString(key.Marshal()))
		}
		for _, frag := range sshKeyFragmentPattern.FindAllString(line, -1) {
			add(frag)
		}
	}
	sort.Slice(known, func(i, j int) bool { return len(known[i]) > len(known[j]) })
	return known
}

func decodeRawJSON(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func scrubJSONString(s string, known []string, freeText bool) (string, bool) {
	out := s
	for _, item := range known {
		if item != "" && strings.Contains(out, item) {
			out = strings.ReplaceAll(out, item, hiddenTailnetKey)
		}
	}
	if freeText {
		out = scrubTailnetText(out)
	}
	return out, out != s
}

func scrubJSONValue(v any, known []string, freeText bool) (any, bool, error) {
	switch val := v.(type) {
	case string:
		s, c := scrubJSONString(val, known, freeText)
		return s, c, nil
	case []any:
		changed := false
		out := make([]any, len(val))
		for i, item := range val {
			nv, c, err := scrubJSONValue(item, known, freeText)
			if err != nil {
				return nil, false, err
			}
			out[i] = nv
			changed = changed || c
		}
		return out, changed, nil
	case map[string]any:
		changed := false
		out := make(map[string]any, len(val))
		used := make(map[string]bool, len(val))
		for k, item := range val {
			nk, kc := scrubJSONString(k, known, false)
			if used[nk] {
				return nil, false, errInvalidTailnetState
			}
			used[nk] = true
			nv, vc, err := scrubJSONValue(item, known, freeText)
			if err != nil {
				return nil, false, err
			}
			out[nk] = nv
			changed = changed || kc || vc
		}
		return out, changed, nil
	default:
		return v, false, nil
	}
}

func scrubHealthValue(v any, known []string) (any, bool, error) {
	arr, ok := v.([]any)
	if !ok {
		return scrubJSONValue(v, known, false)
	}
	changed := false
	out := make([]any, len(arr))
	for i, item := range arr {
		if s, ok := item.(string); ok {
			ns, c := scrubJSONString(s, known, true)
			out[i] = ns
			changed = changed || c
			continue
		}
		nv, c, err := scrubJSONValue(item, known, false)
		if err != nil {
			return nil, false, err
		}
		out[i] = nv
		changed = changed || c
	}
	return out, changed, nil
}

func scrubTailnetField(name string, raw json.RawMessage, known []string) (json.RawMessage, error) {
	v, err := decodeRawJSON(raw)
	if err != nil {
		return raw, nil
	}
	var (
		out     any
		changed bool
	)
	switch name {
	case "error":
		if s, ok := v.(string); ok {
			out, changed = scrubJSONString(s, known, true)
		} else {
			out, changed, err = scrubJSONValue(v, known, false)
		}
	case "health":
		out, changed, err = scrubHealthValue(v, known)
	default:
		out, changed, err = scrubJSONValue(v, known, false)
	}
	if err != nil {
		return nil, err
	}
	if !changed {
		return raw, nil
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, errInvalidTailnetState
	}
	return encoded, nil
}

func maskTailnetState(result map[string]json.RawMessage) ([]byte, error) {
	lines, err := decodeTailnetKeyLines(result)
	if err != nil {
		return nil, err
	}
	metas := make([]sshKeyMeta, 0, len(lines))
	seen := make(map[string]bool, len(lines))
	for _, line := range lines {
		id, keyType, comment, _ := parseTailnetKeyLine(line)
		if seen[id] {
			continue
		}
		seen[id] = true
		metas = append(metas, sshKeyMeta{ID: id, Type: keyType, Comment: comment})
	}
	encoded, err := json.Marshal(metas)
	if err != nil {
		return nil, errInvalidTailnetState
	}
	known := collectTailnetKeyMaterial(lines)
	out := make(map[string]json.RawMessage, len(result)+1)
	used := map[string]bool{"ssh_keys": true}
	for name, raw := range result {
		if name == "keys" {
			continue
		}
		newName, _ := scrubJSONString(name, known, false)
		if used[newName] {
			return nil, errInvalidTailnetState
		}
		used[newName] = true
		scrubbed, err := scrubTailnetField(name, raw, known)
		if err != nil {
			return nil, err
		}
		out[newName] = scrubbed
	}
	out["ssh_keys"] = encoded
	masked, err := json.Marshal(out)
	if err != nil {
		return nil, errInvalidTailnetState
	}
	return masked, nil
}

func (s *Server) callTailnet(ctx context.Context, token, action, key, host string, port int) (map[string]json.RawMessage, error) {
	body, _ := json.Marshal(struct {
		Action string `json:"action"`
		Key    string `json:"key,omitempty"`
		Host   string `json:"host,omitempty"`
		Port   int    `json:"port,omitempty"`
	}{action, key, host, port})
	data, err := s.guestAPI(ctx, token, http.MethodPost, "/tailnet", body)
	if err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(data, &result) != nil {
		return nil, errInvalidTailnetState
	}
	return result, nil
}

func writeTailnetCallError(w http.ResponseWriter, err error) {
	if errors.Is(err, errInvalidTailnetState) {
		http.Error(w, errInvalidTailnetState.Error(), http.StatusBadGateway)
		return
	}
	http.Error(w, "Tailscale 操作未完成。请更新环境组件后重试；原设备身份和 SSH 公钥会保留。", http.StatusBadGateway)
}

func writeTailnetGuestError(w http.ResponseWriter, result map[string]json.RawMessage) bool {
	if b := result["tailnet_error"]; len(b) > 0 {
		var reason string
		_ = json.Unmarshal(b, &reason)
		http.Error(w, scrubTailnetText(reason), http.StatusBadGateway)
		return true
	}
	return false
}

func (s *Server) writeMaskedTailnetState(w http.ResponseWriter, result map[string]json.RawMessage) {
	if writeTailnetGuestError(w, result) {
		return
	}
	var authURL string
	_ = json.Unmarshal(result["auth_url"], &authURL)
	if authURL != "" && !validTailnetAuthURL(authURL) {
		http.Error(w, "Tailscale 登录地址无效，请重新发起登录", http.StatusBadGateway)
		return
	}
	masked, err := maskTailnetState(result)
	if err != nil {
		http.Error(w, errInvalidTailnetState.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(masked)
}

func (s *Server) revealTailnetKey(w http.ResponseWriter, r *http.Request, id, password string) {
	if id == "" || len(id) > 128 {
		http.Error(w, "请选择要查看的公钥", http.StatusBadRequest)
		return
	}
	if err := s.account.reauthenticate(password, "查看公钥前，请在本机的「设置 → 账户」设置密码"); err != nil {
		requestError(w, err)
		return
	}
	s.mu.Lock()
	ready, token := s.ready, s.credentials.Token
	busy := s.jobs.snapshot().Running
	s.mu.Unlock()
	if !ready || busy {
		http.Error(w, "请先启动 Cage 环境，并等待当前操作完成", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result, err := s.callTailnet(ctx, token, "status", "", "", 0)
	if err != nil {
		writeTailnetCallError(w, err)
		return
	}
	if writeTailnetGuestError(w, result) {
		return
	}
	lines, err := decodeTailnetKeyLines(result)
	if err != nil {
		http.Error(w, errInvalidTailnetState.Error(), http.StatusBadGateway)
		return
	}
	for _, line := range lines {
		parsedID, _, _, _ := parseTailnetKeyLine(line)
		if parsedID == id {
			jsonReply(w, map[string]string{"id": id, "key": line})
			return
		}
	}
	http.Error(w, "公钥不存在，请刷新后重试", http.StatusBadRequest)
}

func (s *Server) removeTailnetKeyByID(w http.ResponseWriter, r *http.Request, token, id string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result, err := s.callTailnet(ctx, token, "status", "", "", 0)
	if err != nil {
		writeTailnetCallError(w, err)
		return
	}
	if writeTailnetGuestError(w, result) {
		return
	}
	lines, err := decodeTailnetKeyLines(result)
	if err != nil {
		http.Error(w, errInvalidTailnetState.Error(), http.StatusBadGateway)
		return
	}
	matches := uniqueTailnetKeyLines(matchingTailnetKeyLines(lines, id))
	if len(matches) == 0 {
		s.writeMaskedTailnetState(w, result)
		return
	}
	var last map[string]json.RawMessage
	for _, line := range matches {
		last, err = s.callTailnet(ctx, token, "remove-key", line, "", 0)
		if err != nil {
			writeTailnetCallError(w, err)
			return
		}
		if writeTailnetGuestError(w, last) {
			return
		}
	}
	remaining, err := decodeTailnetKeyLines(last)
	if err != nil {
		http.Error(w, errInvalidTailnetState.Error(), http.StatusBadGateway)
		return
	}
	if len(matchingTailnetKeyLines(remaining, id)) > 0 {
		http.Error(w, "公钥未能移除，请刷新后重试", http.StatusBadGateway)
		return
	}
	s.writeMaskedTailnetState(w, last)
}
