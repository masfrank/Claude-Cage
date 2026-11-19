package workbench

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sylvinus/agent-vm/internal/host"
)

var controlURLVectors = []struct {
	in  string
	out string
	ok  bool
}{
	{"", "", true},
	{"  ", "", true},
	{"https://headscale.example.com", "https://headscale.example.com", true},
	{"HTTPS://Headscale.Example.COM", "https://headscale.example.com", true},
	{"https://headscale.example.com:443", "https://headscale.example.com", true},
	{"https://headscale.example.com/", "https://headscale.example.com", true},
	{"https://headscale.example.com:443/", "https://headscale.example.com", true},
	{"https://headscale.example.com:8443", "https://headscale.example.com:8443", true},
	{"https://127.0.0.1", "https://127.0.0.1", true},
	{"https://[::1]", "https://[::1]", true},
	{"https://[::1]:443", "https://[::1]", true},
	{"https://[::1]:8443", "https://[::1]:8443", true},
	{"https://[2001:db8::1]", "https://[2001:db8::1]", true},
	{"https://[2001:db8::1]:443", "https://[2001:db8::1]", true},
	{"https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443", true},
	{"https://[2001:DB8::1]:443/", "https://[2001:db8::1]", true},
	{"https://xn--bcher-kva.example", "https://xn--bcher-kva.example", true},
	{"https://XN--BCHER-KVA.EXAMPLE:443/", "https://xn--bcher-kva.example", true},
	{"https://bücher.example", "https://bücher.example", true},
	{"  https://hs.example.com  ", "https://hs.example.com", true},
	{"https://login.tailscale.com", "", true},
	{"https://controlplane.tailscale.com", "", true},
	{"HTTPS://LOGIN.TAILSCALE.COM:443/", "", true},
	{"http://headscale.example.com", "", false},
	{"https://user:pass@headscale.example.com", "", false},
	{"https://user@headscale.example.com", "", false},
	{"https://headscale.example.com/headscale", "", false},
	{"https://headscale.example.com?x=1", "", false},
	{"https://headscale.example.com#frag", "", false},
	{"https://", "", false},
	{"https://headscale.example.com:0", "", false},
	{"https://headscale.example.com:65536", "", false},
	{"https://headscale.example.com:abc", "", false},
	{"https://headscale.example.com:0443", "", false},
	{"https://headscale.example.com?", "", false},
	{"https://headscale.example.com/ path", "", false},
	{"https://head scale.example.com", "", false},
	{"https://headscale.example.com\\foo", "", false},
	{"https://headscale.example.com%2f", "", false},
	{"https://" + strings.Repeat("a", 1020), "", false},
	{"https://headscale.example.com/" + string(rune(1)), "", false},
}

func TestNormalizeControlURL(t *testing.T) {
	for _, c := range controlURLVectors {
		got, err := normalizeControlURL(c.in)
		if c.ok {
			if err != nil || got != c.out {
				t.Fatalf("%q: got %q %v, want %q", c.in, got, err, c.out)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%q: accepted as %q", c.in, got)
		}
	}
}

func TestValidCustomTailnetAuthURL(t *testing.T) {
	for _, c := range []struct {
		raw, desired string
		ok           bool
	}{
		{"https://hs.example.com/register/abc", "https://hs.example.com", true},
		{"https://HS.Example.COM:443/register/abc", "https://hs.example.com", true},
		{"https://hs.example.com/a/x", "https://hs.example.com", true},
		{"https://HS.EXAMPLE.COM/register/abc", "https://hs.example.com", true},
		{"https://hs.example.com:8443/register/abc", "https://hs.example.com:8443", true},
		{"https://[2001:db8::1]:8443/register/abc", "https://[2001:db8::1]:8443", true},
		{"https://[2001:DB8::1]:8443/register/abc", "https://[2001:db8::1]:8443", true},
		{"https://[2001:db8::1]:443/register/abc", "https://[2001:db8::1]", true},
		{"https://[2001:db8::1]/register/abc", "https://[2001:db8::1]:8443", false},
		{"https://[2001:db8::1]:8444/register/abc", "https://[2001:db8::1]:8443", false},
		{"https://[2001:db8::2]:8443/register/abc", "https://[2001:db8::1]:8443", false},
		{"https://hs.example.com:0/register/abc", "https://hs.example.com", false},
		{"https://hs.example.com:65536/register/abc", "https://hs.example.com", false},
		{"https://hs.example.com:08443/register/abc", "https://hs.example.com:8443", false},
		{"https://hs.example.com:abc/register/abc", "https://hs.example.com", false},
		{"https://bücher.example/register/abc", "https://xn--bcher-kva.example", false},
		{"https://hs.example.com./register/x", "https://hs.example.com", false},
		{"https://hs%2eexample.com/register/abc", "https://hs.example.com", false},
		{"https://hs.example.com.evil.test/register/abc", "https://hs.example.com", false},
		{"https://hs.example.com:8443/register/abc", "https://hs.example.com", false},
		{"https://user@hs.example.com/register/abc", "https://hs.example.com", false},
		{"https://hs.example.com/register/abc#x", "https://hs.example.com", false},
		{"http://hs.example.com/register/abc", "https://hs.example.com", false},
		{"https://hs.example.com\\register", "https://hs.example.com", false},
		{"javascript:alert(1)", "https://hs.example.com", false},
		{"//hs.example.com/register/abc", "https://hs.example.com", false},
		{"https://xn--hs-example-com.test/register/abc", "https://hs.example.com", false},
	} {
		if got := validCustomTailnetAuthURL(c.raw, c.desired); got != c.ok {
			t.Fatalf("%q desired %q: got %v want %v", c.raw, c.desired, got, c.ok)
		}
	}
}

func readyTailnet(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	s.ready = true
	s.credentials.Token = "test-tailnet-token"
	return s
}

type recordedGuest struct {
	mu      sync.Mutex
	reqs    []map[string]any
	fn      func(req map[string]any, n int) any
	delay   time.Duration
	delayOn string
}

func (g *recordedGuest) attach(t *testing.T, s *Server) {
	t.Helper()
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input map[string]any
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		g.mu.Lock()
		g.reqs = append(g.reqs, input)
		n := len(g.reqs)
		fn, delay, delayOn := g.fn, g.delay, g.delayOn
		g.mu.Unlock()
		action, _ := input["action"].(string)
		if delay > 0 && (delayOn == "" || delayOn == action) {
			time.Sleep(delay)
		}
		_ = json.NewEncoder(w).Encode(fn(input, n))
	}))
	s.browserControl = localBrowserClient(t, s.lifetimeContext(), guest)
	t.Cleanup(guest.Close)
}

func (g *recordedGuest) actions() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, len(g.reqs))
	for i, req := range g.reqs {
		out[i], _ = req["action"].(string)
	}
	return out
}

func (g *recordedGuest) nth(i int) map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.reqs[i]
}

func supportedState(extra map[string]any) map[string]any {
	st := map[string]any{"installed": true, "enabled": true, "backend": "Running", "control_url": "", "capabilities": []string{"control-url"}, "ips": []any{}, "peers": []any{}, "keys": []any{}, "forwards": []any{}}
	for k, v := range extra {
		st[k] = v
	}
	return st
}

func decodeTailnetBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if json.Unmarshal(w.Body.Bytes(), &m) != nil {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	return m
}

func TestTailnetOfficialPostSendsEmptyControlURL(t *testing.T) {
	s := readyTailnet(t)
	g := &recordedGuest{fn: func(map[string]any, int) any {
		return supportedState(map[string]any{"backend": "NeedsLogin", "auth_url": "https://login.tailscale.com/a/test"})
	}}
	g.attach(t, s)
	w := request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if got := g.actions(); len(got) != 2 || got[0] != "status" || got[1] != "connect" {
		t.Fatal(got)
	}
	if _, ok := g.nth(0)["control_url"]; ok {
		t.Fatal("GET/probe must not send control_url")
	}
	if g.nth(1)["control_url"] != "" {
		t.Fatal(g.nth(1))
	}
	w = request(s, "GET", "/api/tailscale", s.origin, "", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, ok := g.nth(2)["control_url"]; ok {
		t.Fatal(g.nth(2))
	}
}

func TestTailnetCustomConnectHomologousAndForeignAuth(t *testing.T) {
	s := readyTailnet(t)
	if err := s.writeDesiredControlURL("https://hs.example.com"); err != nil {
		t.Fatal(err)
	}
	g := &recordedGuest{fn: func(req map[string]any, n int) any {
		return supportedState(map[string]any{"control_url": "https://hs.example.com", "backend": "NeedsLogin", "auth_url": "https://hs.example.com/register/abc"})
	}}
	g.attach(t, s)
	w := request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "hs.example.com/register") {
		t.Fatal(w.Code, w.Body.String())
	}
	if g.nth(1)["control_url"] != "https://hs.example.com" {
		t.Fatal(g.nth(1))
	}
	g.fn = func(map[string]any, int) any {
		return supportedState(map[string]any{"control_url": "https://hs.example.com", "backend": "NeedsLogin", "auth_url": "https://login.tailscale.com/a/test"})
	}
	w = request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
	if w.Code != 502 || w.Header().Get("X-Cage-Recovery") != tailnetAuthURLInvalid {
		t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String())
	}
}

func TestTailnetLegacyCustomBlocksMutation(t *testing.T) {
	s := readyTailnet(t)
	if err := s.writeDesiredControlURL("https://hs.example.com"); err != nil {
		t.Fatal(err)
	}
	g := &recordedGuest{fn: func(map[string]any, int) any {
		return map[string]any{"installed": true, "backend": "Running", "auth_url": "https://login.tailscale.com/a/test", "peers": []any{map[string]any{"name": "n", "ip": "100.64.0.1"}}, "ips": []any{"100.64.0.2"}}
	}}
	g.attach(t, s)
	w := request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
	if w.Code != 409 || w.Header().Get("X-Cage-Recovery") != tailnetControlUnsupported {
		t.Fatal(w.Code, w.Body.String())
	}
	if got := g.actions(); len(got) != 1 || got[0] != "status" {
		t.Fatal(got)
	}
	w = request(s, "GET", "/api/tailscale", s.origin, "", true)
	body := decodeTailnetBody(t, w)
	if body["control_url_status"] != "unsupported" || body["auth_url"] != nil {
		t.Fatal(body)
	}
	if peers, _ := body["peers"].([]any); len(peers) != 0 {
		t.Fatal(body["peers"])
	}
}

func TestTailnetMismatchStripsFields(t *testing.T) {
	s := readyTailnet(t)
	if err := s.writeDesiredControlURL("https://hs.example.com"); err != nil {
		t.Fatal(err)
	}
	g := &recordedGuest{fn: func(map[string]any, int) any {
		return supportedState(map[string]any{"control_url": "", "backend": "Running", "auth_url": "https://login.tailscale.com/a/test", "tailnet": "work.test", "peers": []any{map[string]any{"name": "n", "ip": "100.64.0.1"}}, "ips": []any{"100.64.0.2"}, "proxy_url": "http://127.0.0.1"})
	}}
	g.attach(t, s)
	w := request(s, "GET", "/api/tailscale", s.origin, "", true)
	body := decodeTailnetBody(t, w)
	if w.Code != 200 || body["control_url_status"] != "mismatch" || body["control_url_applied"] != "" || body["auth_url"] != nil || body["tailnet"] != nil {
		t.Fatal(w.Code, body)
	}
}

func TestTailnetControlServerBranches(t *testing.T) {
	t.Run("C1", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(""); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(req map[string]any, n int) any {
			if req["action"] == "control-server" {
				return map[string]any{"tailnet_error": "boom"}
			}
			return supportedState(nil)
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
		if w.Code != 502 || w.Header().Get("X-Cage-Recovery") != tailnetControlPending {
			t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String())
		}
		desired, err := s.readDesiredControlURL()
		if err != nil || desired != "" {
			t.Fatal(desired, err)
		}
	})
	t.Run("C2", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(req map[string]any, n int) any {
			if req["action"] == "control-server" {
				return supportedState(map[string]any{"control_url": ""})
			}
			return supportedState(nil)
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
		if w.Code != 502 || w.Header().Get("X-Cage-Recovery") != tailnetControlPending {
			t.Fatal(w.Code, w.Body.String())
		}
	})
	t.Run("C3Restored", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(""); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(req map[string]any, n int) any {
			if req["action"] == "control-server" {
				if req["control_url"] == "https://hs.example.com" {
					_ = os.Remove(s.tailscalePath())
					_ = os.Mkdir(s.tailscalePath(), 0700)
					return supportedState(map[string]any{"control_url": "https://hs.example.com"})
				}
				return supportedState(map[string]any{"control_url": ""})
			}
			return supportedState(nil)
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
		if w.Code != 500 || w.Header().Get("X-Cage-Recovery") != tailnetControlRestored {
			t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String())
		}
		if got := g.actions(); len(got) != 3 || got[2] != "control-server" || g.nth(2)["control_url"] != "" {
			t.Fatal(got, g.nth(2))
		}
	})
	t.Run("C3Pending", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(""); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(req map[string]any, n int) any {
			if req["action"] == "control-server" {
				if req["control_url"] == "https://hs.example.com" {
					_ = os.Remove(s.tailscalePath())
					_ = os.Mkdir(s.tailscalePath(), 0700)
					return supportedState(map[string]any{"control_url": "https://hs.example.com"})
				}
				return map[string]any{"tailnet_error": "compensate failed"}
			}
			return supportedState(nil)
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
		if w.Code != 500 || w.Header().Get("X-Cage-Recovery") != tailnetControlPending {
			t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String())
		}
	})
	t.Run("C4", func(t *testing.T) {
		s := readyTailnet(t)
		if err := os.Mkdir(s.tailscalePath(), 0700); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(req map[string]any, n int) any {
			if req["action"] == "control-server" {
				return supportedState(map[string]any{"control_url": "https://hs.example.com"})
			}
			return supportedState(nil)
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
		if w.Code != 500 || w.Header().Get("X-Cage-Recovery") != tailnetControlPending {
			t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String())
		}
		if got := g.actions(); len(got) != 2 {
			t.Fatal(got)
		}
	})
	t.Run("legacyOfficialNoSwitch", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return map[string]any{"installed": true, "backend": "Running"}
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":""}`, true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if got := g.actions(); len(got) != 1 || got[0] != "status" {
			t.Fatal(got)
		}
	})
}

func TestTailnetControlServerInput(t *testing.T) {
	s := readyTailnet(t)
	g := &recordedGuest{fn: func(map[string]any, int) any { return supportedState(nil) }}
	g.attach(t, s)
	for _, body := range []string{`{}`, `{"control_url":null}`, `{"control_url":1}`, `{"control_url":true}`} {
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, body, true)
		if w.Code != 400 || len(g.actions()) != 0 {
			t.Fatalf("%s: %d %s %v", body, w.Code, w.Body.String(), g.actions())
		}
	}
	w := request(s, "POST", "/api/tailscale/connect", s.origin, `{"control_url":""}`, true)
	if w.Code != 400 || len(g.actions()) != 0 {
		t.Fatal(w.Code, w.Body.String(), g.actions())
	}
	w = request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"http://hs.example.com"}`, true)
	if w.Code != 400 || w.Header().Get("X-Cage-Recovery") != tailnetControlInvalid || len(g.actions()) != 0 {
		t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String())
	}
}

func TestTailnetAdmissionAndUnreadable(t *testing.T) {
	s := readyTailnet(t)
	g := &recordedGuest{fn: func(map[string]any, int) any { return supportedState(nil) }}
	g.attach(t, s)
	s.op.Lock()
	w := request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "其他操作") {
		s.op.Unlock()
		t.Fatal(w.Code, w.Body.String())
	}
	w = request(s, "GET", "/api/tailscale", s.origin, "", true)
	if w.Code != 200 {
		s.op.Unlock()
		t.Fatal(w.Code, w.Body.String())
	}
	s.op.Unlock()
	s.closing = true
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", s.origin+"/api/tailscale/connect", strings.NewReader("{}"))
	s.handleTailnetAction(rec, req, "connect", "", "", "", 0)
	if rec.Code != 409 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	s.closing = false
	s.ready = false
	w = request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	s.ready = true
	s.setJobForTest(Job{Running: true, Kind: "start"})
	w = request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	s.setJobForTest(Job{})
	if err := os.WriteFile(s.tailscalePath(), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	before := len(g.actions())
	w = request(s, "GET", "/api/tailscale", s.origin, "", true)
	if w.Code != 500 || w.Header().Get("X-Cage-Recovery") != tailnetControlUnreadable || len(g.actions()) != before {
		t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String(), g.actions())
	}
}

func TestTailnetUnreadableControlURLDoesNotReachGuest(t *testing.T) {
	s := readyTailnet(t)
	g := &recordedGuest{fn: func(req map[string]any, n int) any {
		if u, ok := req["control_url"].(string); ok {
			return supportedState(map[string]any{"control_url": u})
		}
		return supportedState(nil)
	}}
	g.attach(t, s)
	for _, body := range []string{
		`{"control_url":null}`,
		`{"control_url":1}`,
		`{`,
		`null`,
		`1`,
	} {
		if err := os.WriteFile(s.tailscalePath(), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		before := len(g.actions())
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 500 || w.Header().Get("X-Cage-Recovery") != tailnetControlUnreadable || !strings.Contains(w.Body.String(), errTailnetUnreadable.Error()) || len(g.actions()) != before {
			t.Fatalf("%s GET: %d %s %q %v", body, w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String(), g.actions())
		}
		w = request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
		if w.Code != 500 || w.Header().Get("X-Cage-Recovery") != tailnetControlUnreadable || len(g.actions()) != before {
			t.Fatalf("%s POST: %d %s %q %v", body, w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String(), g.actions())
		}
	}
	if err := os.WriteFile(s.tailscalePath(), []byte(`{"control_url":null}`), 0600); err != nil {
		t.Fatal(err)
	}
	w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	desired, err := s.readDesiredControlURL()
	if err != nil || desired != "https://hs.example.com" {
		t.Fatal(desired, err)
	}
	w = request(s, "GET", "/api/tailscale", s.origin, "", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if got := g.actions(); len(got) < 2 || got[len(got)-1] != "status" {
		t.Fatal(got)
	}
}

func TestTailnetMissingOrEmptyControlURLIsOfficial(t *testing.T) {
	s := readyTailnet(t)
	g := &recordedGuest{fn: func(map[string]any, int) any { return supportedState(nil) }}
	g.attach(t, s)
	for _, body := range []string{`{}`, `{"control_url":""}`} {
		if err := os.WriteFile(s.tailscalePath(), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		before := len(g.actions())
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 200 || len(g.actions()) != before+1 {
			t.Fatalf("%s: %d %s %v", body, w.Code, w.Body.String(), g.actions())
		}
		desired, err := s.readDesiredControlURL()
		if err != nil || desired != "" {
			t.Fatal(desired, err)
		}
	}
}

func TestTailnetFilePermissions(t *testing.T) {
	s := readyTailnet(t)
	g := &recordedGuest{fn: func(map[string]any, int) any {
		return map[string]any{"installed": false, "enabled": false, "backend": "NotInstalled", "ips": []any{}, "peers": []any{}, "keys": []any{}}
	}}
	g.attach(t, s)
	w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := host.CheckPrivateFile(s.tailscalePath()); err != nil {
		t.Fatal(err)
	}
	var file struct {
		ControlURL string `json:"control_url"`
	}
	b, err := os.ReadFile(s.tailscalePath())
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(b, &file) != nil || file.ControlURL != "https://hs.example.com" {
		t.Fatal(string(b))
	}
}

func TestAgentControlServerCapability(t *testing.T) {
	for _, op := range AgentOperations() {
		if op.Name == "tailscale.control-server" {
			if op.path != "/api/tailscale/control-server" {
				t.Fatal(op.path)
			}
			return
		}
	}
	t.Fatal("missing tailscale.control-server")
}

func TestTailnetStrandedAndLegacy(t *testing.T) {
	stranded := func(applied string) map[string]any {
		return map[string]any{"installed": true, "backend": "Running", "control_url": applied, "auth_url": "https://login.tailscale.com/a/test", "peers": []any{map[string]any{"name": "n"}}, "ips": []any{"100.64.0.2"}}
	}
	t.Run("strandedCustomVsOfficial", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(map[string]any, int) any { return stranded("https://hs.example.com") }}
		g.attach(t, s)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		body := decodeTailnetBody(t, w)
		if body["control_url_status"] != "unsupported" || body["auth_url"] != nil {
			t.Fatal(body)
		}
		w = request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
		if w.Code != 409 || w.Header().Get("X-Cage-Recovery") != tailnetControlUnsupported {
			t.Fatal(w.Code, w.Body.String())
		}
		if got := g.actions(); got[len(got)-1] != "status" {
			t.Fatal(got)
		}
		before := len(g.actions())
		w = request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":""}`, true)
		if w.Code != 409 || len(g.actions()) != before+1 {
			t.Fatal(w.Code, g.actions())
		}
		desired, _ := s.readDesiredControlURL()
		if desired != "" {
			t.Fatal(desired)
		}
	})
	t.Run("strandedMatchesCustom", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL("https://hs.example.com"); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return map[string]any{"installed": true, "backend": "Running", "control_url": "https://hs.example.com"}
		}}
		g.attach(t, s)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		body := decodeTailnetBody(t, w)
		if body["control_url_status"] != "ok" {
			t.Fatal(body)
		}
		w = request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if got := g.actions(); got[len(got)-1] != "connect" {
			t.Fatal(got)
		}
		if _, ok := g.nth(len(g.actions()) - 1)["control_url"]; ok {
			t.Fatal("stranded must not forward control_url")
		}
	})
	t.Run("strandedOfficial", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(map[string]any, int) any { return stranded("") }}
		g.attach(t, s)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if decodeTailnetBody(t, w)["control_url_status"] != "ok" {
			t.Fatal(w.Body.String())
		}
		w = request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	})
	t.Run("legacyOfficialForwards", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return map[string]any{"installed": true, "backend": "NeedsLogin", "auth_url": "https://login.tailscale.com/a/test"}
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if got := g.actions(); len(got) != 2 || got[0] != "status" || got[1] != "connect" {
			t.Fatal(got)
		}
		if _, ok := g.nth(1)["control_url"]; ok {
			t.Fatal(g.nth(1))
		}
	})
}

func TestTailnetNotInstalledAndSupported(t *testing.T) {
	s := readyTailnet(t)
	g := &recordedGuest{fn: func(req map[string]any, n int) any {
		return map[string]any{"installed": false, "enabled": false, "backend": "NotInstalled", "ips": []any{}, "peers": []any{}, "keys": []any{}}
	}}
	g.attach(t, s)
	w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if got := g.actions(); len(got) != 1 || got[0] != "status" {
		t.Fatal(got)
	}
	desired, err := s.readDesiredControlURL()
	if err != nil || desired != "https://hs.example.com" {
		t.Fatal(desired, err)
	}
	w = request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if got := g.actions(); got[len(got)-1] != "connect" {
		t.Fatal(got)
	}
}

func TestTailnetG5HealthPassthrough(t *testing.T) {
	s := readyTailnet(t)
	if err := s.writeDesiredControlURL("https://hs.example.com"); err != nil {
		t.Fatal(err)
	}
	health := []string{"Tailscale 未能启动：dir exists"}
	g := &recordedGuest{fn: func(req map[string]any, n int) any {
		if req["action"] == "connect" {
			return supportedState(map[string]any{"control_url": "https://hs.example.com", "backend": "Running", "health": []any{}})
		}
		return supportedState(map[string]any{"control_url": "https://hs.example.com", "backend": "Stopped", "health": health})
	}}
	g.attach(t, s)
	w := request(s, "GET", "/api/tailscale", s.origin, "", true)
	body := decodeTailnetBody(t, w)
	h, _ := body["health"].([]any)
	if w.Code != 200 || len(h) == 0 {
		t.Fatal(body)
	}
	w = request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
	body = decodeTailnetBody(t, w)
	h, _ = body["health"].([]any)
	if w.Code != 200 || len(h) != 0 {
		t.Fatal(body)
	}
}

func TestTailnetControlServerTimeout(t *testing.T) {
	s := readyTailnet(t)
	g := &recordedGuest{delay: 16 * time.Second, delayOn: "control-server", fn: func(req map[string]any, n int) any {
		if req["action"] == "control-server" {
			return supportedState(map[string]any{"control_url": "https://hs.example.com"})
		}
		return supportedState(nil)
	}}
	g.attach(t, s)
	w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
	if w.Code != 502 || w.Header().Get("X-Cage-Recovery") != tailnetControlPending {
		t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String())
	}
}

func TestTailnetControlServerAuthURL(t *testing.T) {
	t.Run("supportedCustomForeign", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(req map[string]any, n int) any {
			if req["action"] == "control-server" {
				return supportedState(map[string]any{"control_url": "https://hs.example.com", "backend": "NeedsLogin", "auth_url": "https://evil.test/register/x"})
			}
			return supportedState(nil)
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
		if w.Code != 502 || w.Header().Get("X-Cage-Recovery") != tailnetAuthURLInvalid {
			t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String())
		}
		if strings.Contains(w.Body.String(), "evil.test") {
			t.Fatal(w.Body.String())
		}
	})
	t.Run("supportedCustomHomologous", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(req map[string]any, n int) any {
			if req["action"] == "control-server" {
				return supportedState(map[string]any{"control_url": "https://hs.example.com", "backend": "NeedsLogin", "auth_url": "https://hs.example.com/register/x"})
			}
			return supportedState(nil)
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "https://hs.example.com/register/x") {
			t.Fatal(w.Code, w.Body.String())
		}
	})
	t.Run("supportedOfficialForeign", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(req map[string]any, n int) any {
			if req["action"] == "control-server" {
				return supportedState(map[string]any{"control_url": "", "backend": "NeedsLogin", "auth_url": "https://evil.test/a/x"})
			}
			return supportedState(nil)
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":""}`, true)
		if w.Code != 502 {
			t.Fatal(w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "evil.test") {
			t.Fatal(w.Body.String())
		}
	})
	t.Run("legacyOfficialForeign", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return map[string]any{"installed": true, "backend": "NeedsLogin", "auth_url": "https://evil.test/a/x"}
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":""}`, true)
		if w.Code != 502 {
			t.Fatal(w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "evil.test") {
			t.Fatal(w.Body.String())
		}
	})
	t.Run("strandedCustomForeign", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return map[string]any{"installed": true, "backend": "NeedsLogin", "control_url": "https://hs.example.com", "auth_url": "https://evil.test/register/x"}
		}}
		g.attach(t, s)
		w := request(s, "POST", "/api/tailscale/control-server", s.origin, `{"control_url":"https://hs.example.com"}`, true)
		if w.Code != 502 || w.Header().Get("X-Cage-Recovery") != tailnetAuthURLInvalid {
			t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String())
		}
		if strings.Contains(w.Body.String(), "evil.test") {
			t.Fatal(w.Body.String())
		}
	})
}

func TestTailnetStoppedControlURLStatus(t *testing.T) {
	const desired = "https://hs.example.com"
	t.Run("stoppedOfficialAppliedIsOK", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return supportedState(map[string]any{
				"control_url": "",
				"enabled":     false,
				"backend":     "Stopped",
				"peers":       []any{map[string]any{"name": "n", "ip": "100.64.0.1"}},
				"ips":         []any{"100.64.0.2"},
				"tailnet":     "work.test",
			})
		}}
		g.attach(t, s)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		body := decodeTailnetBody(t, w)
		peers, _ := body["peers"].([]any)
		if w.Code != 200 || body["control_url_status"] != "ok" || body["control_url_applied"] != "" || body["tailnet"] != "work.test" || len(peers) != 1 {
			t.Fatal(w.Code, body)
		}
	})
	t.Run("disabledRunningRemainsMismatch", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return supportedState(map[string]any{
				"control_url": "",
				"enabled":     false,
				"backend":     "Running",
				"auth_url":    "https://login.tailscale.com/a/test",
				"tailnet":     "work.test",
				"peers":       []any{map[string]any{"name": "n", "ip": "100.64.0.1"}},
			})
		}}
		g.attach(t, s)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		body := decodeTailnetBody(t, w)
		peers, _ := body["peers"].([]any)
		if w.Code != 200 || body["control_url_status"] != "mismatch" || body["auth_url"] != nil || body["tailnet"] != nil || len(peers) != 0 {
			t.Fatal(w.Code, body)
		}
	})
	t.Run("enabledStoppedRemainsMismatch", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return supportedState(map[string]any{
				"control_url": "",
				"enabled":     true,
				"backend":     "Stopped",
				"auth_url":    "https://login.tailscale.com/a/test",
				"tailnet":     "work.test",
				"peers":       []any{map[string]any{"name": "n"}},
			})
		}}
		g.attach(t, s)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		body := decodeTailnetBody(t, w)
		peers, _ := body["peers"].([]any)
		if w.Code != 200 || body["control_url_status"] != "mismatch" || body["auth_url"] != nil || body["tailnet"] != nil || len(peers) != 0 {
			t.Fatal(w.Code, body)
		}
	})
	t.Run("invalidAppliedStoppedRemainsMismatch", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return supportedState(map[string]any{
				"control_url": "invalid",
				"enabled":     false,
				"backend":     "Stopped",
				"auth_url":    "https://login.tailscale.com/a/test",
				"peers":       []any{map[string]any{"name": "n"}},
			})
		}}
		g.attach(t, s)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		body := decodeTailnetBody(t, w)
		peers, _ := body["peers"].([]any)
		if w.Code != 200 || body["control_url_status"] != "mismatch" || body["control_url_applied"] != "invalid" || body["auth_url"] != nil || len(peers) != 0 {
			t.Fatal(w.Code, body)
		}
	})
	t.Run("stoppedOKRejectsOfficialAuthURL", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return supportedState(map[string]any{
				"control_url": "",
				"enabled":     false,
				"backend":     "Stopped",
				"auth_url":    "https://login.tailscale.com/a/test",
			})
		}}
		g.attach(t, s)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 502 || w.Header().Get("X-Cage-Recovery") != tailnetAuthURLInvalid {
			t.Fatal(w.Code, w.Header().Get("X-Cage-Recovery"), w.Body.String())
		}
		if strings.Contains(w.Body.String(), "login.tailscale.com") {
			t.Fatal(w.Body.String())
		}
	})
}

func TestApplySavedTailnetControl(t *testing.T) {
	const desired = "https://hs.example.com"
	apply := func(t *testing.T, s *Server, timeout time.Duration) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(s.lifetimeContext(), timeout)
		defer cancel()
		return s.applySavedTailnetControl(ctx)
	}
	t.Run("emptyDesiredNoRequest", func(t *testing.T) {
		s := readyTailnet(t)
		g := &recordedGuest{fn: func(map[string]any, int) any { return supportedState(nil) }}
		g.attach(t, s)
		if err := apply(t, s, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		if got := g.actions(); len(got) != 0 {
			t.Fatal(got)
		}
	})
	t.Run("supportedMismatchSendsControlServer", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(req map[string]any, n int) any {
			if req["action"] == "control-server" {
				return supportedState(map[string]any{"control_url": desired, "enabled": false, "backend": "Stopped"})
			}
			return supportedState(map[string]any{"control_url": "", "enabled": false, "backend": "Stopped"})
		}}
		g.attach(t, s)
		if err := apply(t, s, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		if got := g.actions(); len(got) != 2 || got[0] != "status" || got[1] != "control-server" {
			t.Fatal(got)
		}
		if g.nth(1)["control_url"] != desired {
			t.Fatal(g.nth(1))
		}
	})
	t.Run("appliedEqualsDesiredNoSwitch", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return supportedState(map[string]any{"control_url": desired})
		}}
		g.attach(t, s)
		if err := apply(t, s, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		if got := g.actions(); len(got) != 1 || got[0] != "status" {
			t.Fatal(got)
		}
	})
	t.Run("legacyError", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return map[string]any{"installed": true, "backend": "Running"}
		}}
		g.attach(t, s)
		if err := apply(t, s, 5*time.Second); err == nil || !strings.Contains(err.Error(), "尚未就绪或不支持") {
			t.Fatal(err)
		}
		if got := g.actions(); len(got) != 1 || got[0] != "status" {
			t.Fatal(got)
		}
	})
	t.Run("notInstalledError", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return map[string]any{"installed": false, "enabled": false, "backend": "NotInstalled"}
		}}
		g.attach(t, s)
		if err := apply(t, s, 5*time.Second); err == nil || !strings.Contains(err.Error(), "尚未就绪或不支持") {
			t.Fatal(err)
		}
	})
	t.Run("strandedError", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return map[string]any{"installed": true, "backend": "Running", "control_url": desired}
		}}
		g.attach(t, s)
		if err := apply(t, s, 5*time.Second); err == nil || !strings.Contains(err.Error(), "尚未就绪或不支持") {
			t.Fatal(err)
		}
	})
	t.Run("tailnetError", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(map[string]any, int) any {
			return map[string]any{"tailnet_error": "boom"}
		}}
		g.attach(t, s)
		if err := apply(t, s, 5*time.Second); err == nil || err.Error() != "boom" {
			t.Fatal(err)
		}
	})
	t.Run("controlServerStillMismatch", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{fn: func(req map[string]any, n int) any {
			return supportedState(map[string]any{"control_url": ""})
		}}
		g.attach(t, s)
		if err := apply(t, s, 5*time.Second); err == nil || !strings.Contains(err.Error(), "未切换到已保存的地址") {
			t.Fatal(err)
		}
		if got := g.actions(); len(got) != 2 || got[1] != "control-server" {
			t.Fatal(got)
		}
	})
	t.Run("contextTimeout", func(t *testing.T) {
		s := readyTailnet(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		g := &recordedGuest{delay: 200 * time.Millisecond, fn: func(map[string]any, int) any {
			return supportedState(nil)
		}}
		g.attach(t, s)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if err := s.applySavedTailnetControl(ctx); err == nil {
			t.Fatal("expected timeout")
		}
	})
}

func TestTailnetInstallAndRefreshHooks(t *testing.T) {
	const desired = "https://hs.example.com"
	record := func(t *testing.T) (*Server, *[]string) {
		t.Helper()
		s := readyTailnet(t)
		steps := &[]string{}
		s.tailnetPlaceBinary = func() error {
			*steps = append(*steps, "place")
			return nil
		}
		s.tailnetApplySavedControl = func(context.Context) error {
			*steps = append(*steps, "apply")
			return nil
		}
		return s, steps
	}
	t.Run("refreshInstalledPlacesOnly", func(t *testing.T) {
		s, steps := record(t)
		s.tailnetInstalledProbe = func() (bool, error) { return true, nil }
		if err := s.refreshInstalledTailnet(); err != nil {
			t.Fatal(err)
		}
		if got := *steps; len(got) != 1 || got[0] != "place" {
			t.Fatal(got)
		}
	})
	t.Run("refreshMissingBinaryDoesNothing", func(t *testing.T) {
		s, steps := record(t)
		s.tailnetInstalledProbe = func() (bool, error) { return false, nil }
		if err := s.refreshInstalledTailnet(); err != nil {
			t.Fatal(err)
		}
		if got := *steps; len(got) != 0 {
			t.Fatal(got)
		}
	})
	t.Run("installPlacesThenApplies", func(t *testing.T) {
		s, steps := record(t)
		if err := s.installTailnet(); err != nil {
			t.Fatal(err)
		}
		if got := *steps; len(got) != 2 || got[0] != "place" || got[1] != "apply" {
			t.Fatal(got)
		}
	})
	t.Run("installApplyFailureKeepsR5Message", func(t *testing.T) {
		s, steps := record(t)
		if err := s.writeDesiredControlURL(desired); err != nil {
			t.Fatal(err)
		}
		s.tailnetApplySavedControl = func(context.Context) error {
			*steps = append(*steps, "apply")
			return errors.New("组件尚未就绪或不支持")
		}
		err := s.installTailnet()
		if err == nil || !strings.Contains(err.Error(), "Tailscale 已安装，但未能切换到 "+desired+"：组件尚未就绪或不支持") || !strings.Contains(err.Error(), "连接时会再次尝试") {
			t.Fatal(err)
		}
		if got := *steps; len(got) != 2 || got[0] != "place" || got[1] != "apply" {
			t.Fatal(got)
		}
	})
	t.Run("installPlaceFailureDoesNotApply", func(t *testing.T) {
		s, steps := record(t)
		s.tailnetPlaceBinary = func() error {
			*steps = append(*steps, "place")
			return errors.New("Tailscale 安装未完成，请检查客机连接后重试")
		}
		err := s.installTailnet()
		if err == nil || !strings.Contains(err.Error(), "安装未完成") {
			t.Fatal(err)
		}
		if got := *steps; len(got) != 1 || got[0] != "place" {
			t.Fatal(got)
		}
	})
}
