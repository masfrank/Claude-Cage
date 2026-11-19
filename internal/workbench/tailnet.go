package workbench

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

func validTailnetAuthURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "login.tailscale.com" && u.User == nil && u.Fragment == "" && (len(u.Path) > 3 && (u.Path[:3] == "/a/" || u.Path[:3] == "/c/"))
}
func (s *Server) tailnet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	action := r.PathValue("action")
	if r.Method == http.MethodGet {
		action = "status"
	}
	if action == "install" {
		var input struct{}
		if !readJSON(w, r, &input) {
			return
		}
		s.launch(w, "tailscale-install", s.installTailnet)
		return
	}
	switch action {
	case "status", "connect", "login", "disconnect", "logout", "add-key", "remove-key", "open-service", "control-server", "reveal-key":
	default:
		http.NotFound(w, r)
		return
	}
	var input struct {
		Key             string          `json:"key"`
		ID              string          `json:"id"`
		AccountPassword string          `json:"account_password"`
		Host            string          `json:"host,omitempty"`
		Port            int             `json:"port,omitempty"`
		ControlURL      json.RawMessage `json:"control_url,omitempty"`
	}
	if r.Method != http.MethodGet && !readJSON(w, r, &input) {
		return
	}
	if action == "remove-key" && (input.ID == "") == (input.Key == "") {
		http.Error(w, "请选择要移除的公钥", 400)
		return
	}
	if len(input.Key) > 8192 {
		http.Error(w, "SSH 公钥过长", 400)
		return
	}
	if action == "open-service" && (len(input.Host) == 0 || len(input.Host) > 253 || input.Port < 1 || input.Port > 65535) {
		http.Error(w, "请选择私网设备并填写 1–65535 之间的端口", 400)
		return
	}
	if action == "control-server" {
		next, ok := parseControlServerInput(w, input.ControlURL)
		if !ok {
			return
		}
		s.handleControlServer(w, r, next)
		return
	}
	if len(input.ControlURL) != 0 {
		http.Error(w, "请求格式无效", 400)
		return
	}
	if action == "reveal-key" {
		s.revealTailnetKey(w, r, input.ID, input.AccountPassword)
		return
	}
	s.handleTailnetAction(w, r, action, input.Key, input.ID, input.Host, input.Port)
}

var errTailnetNativeInstall = errors.New("请在设置中更新环境组件，Tailscale 随客机组件一同安装")
