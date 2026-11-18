package workbench

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
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
	case "status", "connect", "login", "disconnect", "logout", "add-key", "remove-key", "open-service", "reveal-key":
	default:
		http.NotFound(w, r)
		return
	}
	var input struct {
		Key             string `json:"key"`
		ID              string `json:"id"`
		AccountPassword string `json:"account_password"`
		Host            string `json:"host,omitempty"`
		Port            int    `json:"port,omitempty"`
	}
	if r.Method != http.MethodGet && !readJSON(w, r, &input) {
		return
	}
	if action == "reveal-key" {
		s.revealTailnetKey(w, r, input.ID, input.AccountPassword)
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
	s.mu.Lock()
	ready, token := s.ready, s.credentials.Token
	busy := s.jobs.snapshot().Running
	s.mu.Unlock()
	if !ready || busy {
		http.Error(w, "请先启动 Cage 环境，并等待当前操作完成", 409)
		return
	}
	if action == "add-key" || action == "remove-key" {
		s.tailnetKeyMu.Lock()
		defer s.tailnetKeyMu.Unlock()
	}
	if action == "remove-key" && input.ID != "" {
		s.removeTailnetKeyByID(w, r, token, input.ID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result, err := s.callTailnet(ctx, token, action, input.Key, input.Host, input.Port)
	if err != nil {
		writeTailnetCallError(w, err)
		return
	}
	s.writeMaskedTailnetState(w, result)
}

var errTailnetNativeInstall = errors.New("请在设置中更新环境组件，Tailscale 随客机组件一同安装")
