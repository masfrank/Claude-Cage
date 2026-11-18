package workbench

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type tailnetGuestInput struct {
	Action string `json:"action"`
	Key    string `json:"key"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

func testAuthorizedKey(t *testing.T, comment string) (line, body, id string) {
	t.Helper()
	rawPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(rawPub)
	if err != nil {
		t.Fatal(err)
	}
	marshaled := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	parts := strings.Fields(marshaled)
	if len(parts) < 2 {
		t.Fatal(marshaled)
	}
	body = parts[1]
	line = marshaled
	if comment != "" {
		line += " " + comment
	}
	return line, body, ssh.FingerprintSHA256(pub)
}

func unknownKeyID(line string) string {
	sum := sha256.Sum256([]byte(line))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func serveTailnetGuest(t *testing.T, s *Server, fn func(http.ResponseWriter, tailnetGuestInput)) {
	t.Helper()
	s.ready = true
	if s.credentials.Token == "" {
		s.credentials.Token = "test-tailnet-token"
	}
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/tailnet" || r.Header.Get("Authorization") != "Bearer "+s.credentials.Token {
			t.Errorf("wrong guest route or credentials: %s %s", r.Method, r.URL.Path)
			http.Error(w, "bad guest", 500)
			return
		}
		var input tailnetGuestInput
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			t.Error("invalid input")
			http.Error(w, "bad json", 400)
			return
		}
		fn(w, input)
	}))
	t.Cleanup(guest.Close)
	s.browserControl = localBrowserClient(t, s.lifetimeContext(), guest)
}

func writeTailnetGuestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func assertNoMaterial(t *testing.T, raw []byte, materials ...string) {
	t.Helper()
	for _, m := range materials {
		if m != "" && bytes.Contains(raw, []byte(m)) {
			t.Fatalf("leaked %q in %s", m, raw)
		}
	}
}

func decodeSSHKeys(t *testing.T, raw []byte) []sshKeyMeta {
	t.Helper()
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		t.Fatalf("json: %s", raw)
	}
	if _, ok := obj["keys"]; ok {
		t.Fatalf("keys present: %s", raw)
	}
	var keys []sshKeyMeta
	if json.Unmarshal(obj["ssh_keys"], &keys) != nil {
		t.Fatalf("ssh_keys: %s", raw)
	}
	return keys
}

func collectDecodedStrings(v any, out *[]string) {
	switch n := v.(type) {
	case string:
		*out = append(*out, n)
	case []any:
		for _, item := range n {
			collectDecodedStrings(item, out)
		}
	case map[string]any:
		for k, item := range n {
			*out = append(*out, k)
			collectDecodedStrings(item, out)
		}
	}
}

func TestTailnetKeyListMasking(t *testing.T) {
	named, namedBody, namedID := testAuthorizedKey(t, "local")
	plain, plainBody, plainID := testAuthorizedKey(t, "")
	garbage := "not-a-valid-ssh-key"
	optLine, optBody, _ := testAuthorizedKey(t, "opt")
	options := `command="x" ` + optLine
	firstSeg, firstBody, _ := testAuthorizedKey(t, "")
	secondSeg, secondBody, _ := testAuthorizedKey(t, "")
	multi := firstSeg + "\n" + secondSeg
	namedDup := ssh.KeyAlgoED25519 + " " + namedBody + " other-comment"
	_, otherBody, _ := testAuthorizedKey(t, "hidden")
	secretLine, secretBody, secretID := testAuthorizedKey(t, "note "+otherBody)
	_, leakBody, _ := testAuthorizedKey(t, "")
	stripped := strings.TrimPrefix(leakBody, "AAAA")
	if len(stripped) < 40 {
		t.Fatal("stripped fragment too short")
	}
	stripLine, stripBody, stripID := testAuthorizedKey(t, stripped)
	shortFrag := strings.Repeat("n", 39)
	shortLine, shortBody, shortID := testAuthorizedKey(t, "ok-"+shortFrag)

	keys := []string{named, plain, garbage, options, multi, namedDup, secretLine, stripLine, shortLine}
	s := testServer(t)
	serveTailnetGuest(t, s, func(w http.ResponseWriter, _ tailnetGuestInput) {
		writeTailnetGuestJSON(w, map[string]any{"installed": true, "backend": "Running", "keys": keys})
	})
	w := request(s, "GET", "/api/tailscale", s.origin, "", true)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	raw := w.Body.Bytes()
	got := decodeSSHKeys(t, raw)
	want := []sshKeyMeta{
		{ID: namedID, Type: ssh.KeyAlgoED25519, Comment: "local"},
		{ID: plainID, Type: ssh.KeyAlgoED25519, Comment: ""},
		{ID: unknownKeyID(garbage), Type: "unknown", Comment: ""},
		{ID: unknownKeyID(options), Type: "unknown", Comment: ""},
		{ID: unknownKeyID(multi), Type: "unknown", Comment: ""},
		{ID: secretID, Type: ssh.KeyAlgoED25519, Comment: ""},
		{ID: stripID, Type: ssh.KeyAlgoED25519, Comment: ""},
		{ID: shortID, Type: ssh.KeyAlgoED25519, Comment: "ok-" + shortFrag},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ssh_keys: got %#v want %#v", got, want)
	}
	if got[0].ID != namedID || got[1].ID != plainID || got[5].ID != secretID {
		t.Fatal("valid fingerprints")
	}
	assertNoMaterial(t, raw, namedBody, plainBody, optBody, firstBody, secondBody, otherBody, secretBody, leakBody, stripped, stripBody, shortBody, garbage, options, multi, namedDup)
	if !bytes.Contains(raw, []byte(shortFrag)) {
		t.Fatal("39-char comment dropped")
	}
}

func TestTailnetKeyAllActionsMasked(t *testing.T) {
	line, body, id := testAuthorizedKey(t, "ops")
	s := testServer(t)
	serveTailnetGuest(t, s, func(w http.ResponseWriter, input tailnetGuestInput) {
		writeTailnetGuestJSON(w, map[string]any{
			"installed": true,
			"backend":   "Running",
			"auth_url":  "https://login.tailscale.com/a/test",
			"keys":      []string{line},
			"forwards":  []map[string]any{{"host": input.Host, "port": input.Port, "address": "127.0.0.1:32123"}},
		})
	})
	cases := []struct{ method, path, body string }{
		{"GET", "/api/tailscale", ""},
		{"POST", "/api/tailscale/status", "{}"},
		{"POST", "/api/tailscale/connect", "{}"},
		{"POST", "/api/tailscale/login", "{}"},
		{"POST", "/api/tailscale/disconnect", "{}"},
		{"POST", "/api/tailscale/logout", "{}"},
		{"POST", "/api/tailscale/add-key", `{"key":"ignored"}`},
		{"POST", "/api/tailscale/remove-key", `{"key":"ignored"}`},
		{"POST", "/api/tailscale/open-service", `{"host":"100.88.2.4","port":8080}`},
	}
	for _, tc := range cases {
		w := request(s, tc.method, tc.path, s.origin, tc.body, true)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
		keys := decodeSSHKeys(t, w.Body.Bytes())
		if len(keys) != 1 || keys[0].ID != id || keys[0].Comment != "ops" {
			t.Fatalf("%s %s keys %#v", tc.method, tc.path, keys)
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	}
}

func TestTailnetKeyShape(t *testing.T) {
	s := testServer(t)
	var payload any
	serveTailnetGuest(t, s, func(w http.ResponseWriter, _ tailnetGuestInput) {
		writeTailnetGuestJSON(w, payload)
	})
	empty := func(raw any) {
		payload = raw
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		keys := decodeSSHKeys(t, w.Body.Bytes())
		if len(keys) != 0 {
			t.Fatalf("%#v", keys)
		}
	}
	empty(map[string]any{"installed": true})
	empty(map[string]any{"installed": true, "keys": nil})

	for _, raw := range []any{
		map[string]any{"keys": ssh.KeyAlgoED25519 + " AAAA"},
		map[string]any{"keys": map[string]any{"k": 1}},
		map[string]any{"keys": []any{1, 2}},
	} {
		payload = raw
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 502 || !strings.Contains(w.Body.String(), "Tailscale 组件返回了无效状态") {
			t.Fatalf("shape: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestTailnetKeyErrorRedaction(t *testing.T) {
	_, body, _ := testAuthorizedKey(t, "")
	fragment := strings.TrimPrefix(body, "AAAA")
	if len(fragment) < 40 {
		t.Fatal(fragment)
	}
	s := testServer(t)
	var reason string
	serveTailnetGuest(t, s, func(w http.ResponseWriter, _ tailnetGuestInput) {
		writeTailnetGuestJSON(w, map[string]string{"tailnet_error": reason})
	})
	for _, leak := range []string{body, fragment, strings.Repeat("B", 40)} {
		reason = "失败 " + leak
		w := request(s, "POST", "/api/tailscale/connect", s.origin, "{}", true)
		if w.Code != 502 {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), leak)
		if !strings.Contains(w.Body.String(), hiddenTailnetKey) {
			t.Fatalf("missing redaction: %s", w.Body.String())
		}
	}
}

func TestTailnetKeyFinalDefense(t *testing.T) {
	line, body, _ := testAuthorizedKey(t, "desk")
	optLine, optBody, _ := testAuthorizedKey(t, "opt")
	options := `command="x" ` + optLine
	authURL := "https://login.tailscale.com/a/test"
	peers := []map[string]string{{"id": "n1", "name": "peer-one"}}

	t.Run("health", func(t *testing.T) {
		s := testServer(t)
		serveTailnetGuest(t, s, func(w http.ResponseWriter, _ tailnetGuestInput) {
			writeTailnetGuestJSON(w, map[string]any{
				"installed": true,
				"backend":   "Running",
				"auth_url":  authURL,
				"peers":     peers,
				"keys":      []string{line},
				"health":    []string{"bad " + body},
			})
		})
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		assertMaskedDefense(t, w.Body.Bytes(), []string{body}, authURL, peers)
	})

	t.Run("structured", func(t *testing.T) {
		s := testServer(t)
		serveTailnetGuest(t, s, func(w http.ResponseWriter, _ tailnetGuestInput) {
			writeTailnetGuestJSON(w, map[string]any{
				"installed": true,
				"backend":   "Running",
				"auth_url":  authURL,
				"peers":     peers,
				"keys":      []string{options},
				"meta":      map[string]string{"token": optBody},
			})
		})
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		assertMaskedDefense(t, w.Body.Bytes(), []string{optBody}, authURL, peers)
	})

	t.Run("escaped", func(t *testing.T) {
		var escaped strings.Builder
		for _, r := range body {
			switch r {
			case 'A':
				escaped.WriteString(`\u0041`)
			case '/':
				escaped.WriteString(`\/`)
			default:
				escaped.WriteRune(r)
			}
		}
		s := testServer(t)
		serveTailnetGuest(t, s, func(w http.ResponseWriter, _ tailnetGuestInput) {
			base, err := json.Marshal(map[string]any{
				"installed": true,
				"backend":   "Running",
				"auth_url":  authURL,
				"peers":     peers,
				"keys":      []string{line},
			})
			if err != nil {
				t.Error(err)
				return
			}
			var obj map[string]json.RawMessage
			if json.Unmarshal(base, &obj) != nil {
				t.Error(base)
				return
			}
			obj["note"] = json.RawMessage(`"` + escaped.String() + `"`)
			writeTailnetGuestJSON(w, obj)
		})
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		assertMaskedDefense(t, w.Body.Bytes(), []string{body}, authURL, peers)
	})
}

func assertMaskedDefense(t *testing.T, raw []byte, materials []string, authURL string, peers any) {
	t.Helper()
	assertNoMaterial(t, raw, materials...)
	var obj any
	if json.Unmarshal(raw, &obj) != nil {
		t.Fatalf("json: %s", raw)
	}
	var decoded []string
	collectDecodedStrings(obj, &decoded)
	for _, s := range decoded {
		for _, m := range materials {
			if m != "" && strings.Contains(s, m) {
				t.Fatalf("decoded leaked %q in %q", m, s)
			}
		}
	}
	var got map[string]json.RawMessage
	if json.Unmarshal(raw, &got) != nil {
		t.Fatal(raw)
	}
	var gotURL string
	if json.Unmarshal(got["auth_url"], &gotURL) != nil || gotURL != authURL {
		t.Fatalf("auth_url: %s", got["auth_url"])
	}
	var gotPeers any
	if json.Unmarshal(got["peers"], &gotPeers) != nil {
		t.Fatal(got["peers"])
	}
	wantPeers, _ := json.Marshal(peers)
	var expected any
	if json.Unmarshal(wantPeers, &expected) != nil {
		t.Fatal(wantPeers)
	}
	if !reflect.DeepEqual(gotPeers, expected) {
		t.Fatalf("peers: %#v %#v", gotPeers, expected)
	}
}

func TestTailnetKeyReveal(t *testing.T) {
	line1, body, id := testAuthorizedKey(t, "one")
	line2 := ssh.KeyAlgoED25519 + " " + body + " two"
	password := "initial-test-password"

	newRevealServer := func(t *testing.T, fn func(http.ResponseWriter, tailnetGuestInput)) *Server {
		t.Helper()
		s := testServer(t)
		s.account = newTestAccount(t)
		if fn != nil {
			serveTailnetGuest(t, s, fn)
		} else {
			s.ready = true
		}
		return s
	}
	keysGuest := func(w http.ResponseWriter, _ tailnetGuestInput) {
		writeTailnetGuestJSON(w, map[string]any{"installed": true, "keys": []string{line1, line2}})
	}
	reveal := func(s *Server, id, pass string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"id": id, "account_password": pass})
		return request(s, "POST", "/api/tailscale/reveal-key", s.origin, string(b), true)
	}

	t.Run("ok", func(t *testing.T) {
		s := newRevealServer(t, keysGuest)
		w := reveal(s, id, password)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var got map[string]string
		if json.Unmarshal(w.Body.Bytes(), &got) != nil || got["id"] != id || got["key"] != line1 {
			t.Fatalf("%s", w.Body.String())
		}
	})
	t.Run("wrong then retry", func(t *testing.T) {
		s := newRevealServer(t, keysGuest)
		w := reveal(s, id, "wrong")
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
		w = reveal(s, id, password)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "请稍后再试") {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("trusted device", func(t *testing.T) {
		s := newRevealServer(t, keysGuest)
		s.account.record.TrustedDevice = randomToken()
		w := reveal(s, id, password)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "查看公钥前，请在本机的「设置 → 账户」设置密码") {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("empty id", func(t *testing.T) {
		s := newRevealServer(t, keysGuest)
		w := reveal(s, "", password)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "请选择要查看的公钥") {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("long id", func(t *testing.T) {
		s := newRevealServer(t, keysGuest)
		w := reveal(s, strings.Repeat("a", 129), password)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "请选择要查看的公钥") {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("unknown id", func(t *testing.T) {
		s := newRevealServer(t, keysGuest)
		w := reveal(s, "SHA256:missing", password)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "公钥不存在，请刷新后重试") {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("not ready", func(t *testing.T) {
		s := testServer(t)
		s.account = newTestAccount(t)
		w := reveal(s, id, password)
		if w.Code != 409 {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("guest down", func(t *testing.T) {
		s := newRevealServer(t, func(w http.ResponseWriter, _ tailnetGuestInput) {
			http.Error(w, "down", 500)
		})
		w := reveal(s, id, password)
		if w.Code != 502 || !strings.Contains(w.Body.String(), "Tailscale 操作未完成") {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("status error", func(t *testing.T) {
		s := newRevealServer(t, func(w http.ResponseWriter, _ tailnetGuestInput) {
			writeTailnetGuestJSON(w, map[string]string{"tailnet_error": "失败 " + body})
		})
		w := reveal(s, id, password)
		if w.Code != 502 {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
}

func TestTailnetKeyRemove(t *testing.T) {
	line1, body, id := testAuthorizedKey(t, "one")
	line2 := ssh.KeyAlgoED25519 + " " + body + " two"

	t.Run("by id duplicates", func(t *testing.T) {
		s := testServer(t)
		var mu sync.Mutex
		keys := []string{line1, line2}
		var removes []string
		serveTailnetGuest(t, s, func(w http.ResponseWriter, input tailnetGuestInput) {
			mu.Lock()
			defer mu.Unlock()
			if input.Action == "remove-key" {
				removes = append(removes, input.Key)
				next := keys[:0]
				for _, k := range keys {
					if k != input.Key {
						next = append(next, k)
					}
				}
				keys = append([]string{}, next...)
			}
			writeTailnetGuestJSON(w, map[string]any{"installed": true, "keys": append([]string{}, keys...)})
		})
		b, _ := json.Marshal(map[string]string{"id": id})
		w := request(s, "POST", "/api/tailscale/remove-key", s.origin, string(b), true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if !reflect.DeepEqual(removes, []string{line1, line2}) {
			t.Fatalf("removes %#v", removes)
		}
		if len(decodeSSHKeys(t, w.Body.Bytes())) != 0 {
			t.Fatal(w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("unknown id", func(t *testing.T) {
		s := testServer(t)
		var removes int
		serveTailnetGuest(t, s, func(w http.ResponseWriter, input tailnetGuestInput) {
			if input.Action == "remove-key" {
				removes++
			}
			writeTailnetGuestJSON(w, map[string]any{"installed": true, "keys": []string{line1}})
		})
		w := request(s, "POST", "/api/tailscale/remove-key", s.origin, `{"id":"SHA256:missing"}`, true)
		if w.Code != 200 || removes != 0 {
			t.Fatal(w.Code, w.Body.String(), removes)
		}
		keys := decodeSSHKeys(t, w.Body.Bytes())
		if len(keys) != 1 || keys[0].ID != id {
			t.Fatal(w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("id and key", func(t *testing.T) {
		s := testServer(t)
		s.ready = true
		w := request(s, "POST", "/api/tailscale/remove-key", s.origin, `{"id":"x","key":"y"}`, true)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "请选择要移除的公钥") {
			t.Fatal(w.Code, w.Body.String())
		}
	})
	t.Run("neither", func(t *testing.T) {
		s := testServer(t)
		s.ready = true
		w := request(s, "POST", "/api/tailscale/remove-key", s.origin, `{}`, true)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "请选择要移除的公钥") {
			t.Fatal(w.Code, w.Body.String())
		}
	})
	t.Run("by key", func(t *testing.T) {
		s := testServer(t)
		var got tailnetGuestInput
		serveTailnetGuest(t, s, func(w http.ResponseWriter, input tailnetGuestInput) {
			got = input
			writeTailnetGuestJSON(w, map[string]any{"installed": true, "keys": []string{}})
		})
		b, _ := json.Marshal(map[string]string{"key": line1})
		w := request(s, "POST", "/api/tailscale/remove-key", s.origin, string(b), true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if got.Action != "remove-key" || got.Key != line1 {
			t.Fatalf("%#v", got)
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("ignored delete", func(t *testing.T) {
		s := testServer(t)
		serveTailnetGuest(t, s, func(w http.ResponseWriter, _ tailnetGuestInput) {
			writeTailnetGuestJSON(w, map[string]any{"installed": true, "keys": []string{line1, line2}})
		})
		b, _ := json.Marshal(map[string]string{"id": id})
		w := request(s, "POST", "/api/tailscale/remove-key", s.origin, string(b), true)
		if w.Code != 502 || !strings.Contains(w.Body.String(), "公钥未能移除，请刷新后重试") {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("serial", func(t *testing.T) {
		s := testServer(t)
		var inFlight atomic.Int32
		var overlapped atomic.Bool
		serveTailnetGuest(t, s, func(w http.ResponseWriter, _ tailnetGuestInput) {
			n := inFlight.Add(1)
			if n > 1 {
				overlapped.Store(true)
			}
			time.Sleep(15 * time.Millisecond)
			inFlight.Add(-1)
			writeTailnetGuestJSON(w, map[string]any{"installed": true, "keys": []string{line1}})
		})
		var wg sync.WaitGroup
		bodyID, _ := json.Marshal(map[string]string{"id": id})
		for i := 0; i < 8; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				request(s, "POST", "/api/tailscale/add-key", s.origin, `{"key":"ignored"}`, true)
			}()
			go func() {
				defer wg.Done()
				request(s, "POST", "/api/tailscale/remove-key", s.origin, string(bodyID), true)
			}()
		}
		wg.Wait()
		if overlapped.Load() {
			t.Fatal("guest calls overlapped")
		}
	})
}

func TestTailnetKeyAgent(t *testing.T) {
	var reveal, remove, get AgentOperation
	for _, op := range AgentOperations() {
		switch op.Name {
		case "tailscale.reveal-key":
			reveal = op
		case "tailscale.remove-key":
			remove = op
		case "tailscale.get":
			get = op
		}
	}
	if reveal.Name == "" || reveal.path != "/api/tailscale/reveal-key" {
		t.Fatal("missing reveal-key")
	}
	revealProps := reveal.InputSchema["properties"].(map[string]any)
	if _, ok := revealProps["id"]; !ok {
		t.Fatal("reveal id")
	}
	if _, ok := revealProps["account_password"]; !ok {
		t.Fatal("reveal password")
	}
	removeProps := remove.InputSchema["properties"].(map[string]any)
	if _, ok := removeProps["id"]; !ok {
		t.Fatal("remove id")
	}
	if !strings.Contains(get.Description, "ssh_keys") || !strings.Contains(get.Description, "tailscale.reveal-key") {
		t.Fatal(get.Description)
	}

	line, body, id := testAuthorizedKey(t, "agent")
	fragment := strings.Repeat("B", 40)
	s := agentTestController(t)
	s.account = newTestAccount(t)
	var mode string
	serveTailnetGuest(t, s, func(w http.ResponseWriter, input tailnetGuestInput) {
		switch mode {
		case "error":
			writeTailnetGuestJSON(w, map[string]string{"tailnet_error": "失败 " + fragment})
		default:
			writeTailnetGuestJSON(w, map[string]any{"installed": true, "keys": []string{line}})
		}
	})

	data, err := AgentCall(context.Background(), s.configPath, "tailscale.get", nil)
	if err != nil {
		t.Fatal(err)
	}
	assertNoMaterial(t, data, body)
	if !bytes.Contains(data, []byte("ssh_keys")) {
		t.Fatalf("%s", data)
	}

	missing, _ := json.Marshal(map[string]string{"id": id})
	_, err = AgentCall(context.Background(), s.configPath, "tailscale.reveal-key", missing)
	var ae *AgentError
	if !errors.As(err, &ae) {
		t.Fatal(err)
	}
	if strings.Contains(ae.Message, body) {
		t.Fatal(ae.Message)
	}
	_, err = AgentCall(context.Background(), s.configPath, "tailscale.reveal-key", parityJSON(t, map[string]string{"id": id, "account_password": "wrong"}))
	if !errors.As(err, &ae) || strings.Contains(ae.Message, body) {
		t.Fatal(err)
	}
	s.account.mu.Lock()
	s.account.nextAttempt = time.Time{}
	s.account.mu.Unlock()
	data, err = AgentCall(context.Background(), s.configPath, "tailscale.reveal-key", parityJSON(t, map[string]string{"id": id, "account_password": "initial-test-password"}))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if json.Unmarshal(data, &got) != nil || got["key"] != line {
		t.Fatalf("%s", data)
	}

	mode = "error"
	_, err = AgentCall(context.Background(), s.configPath, "tailscale.connect", json.RawMessage(`{}`))
	if !errors.As(err, &ae) || strings.Contains(ae.Message, fragment) {
		t.Fatal(err)
	}
}

func escapeTailnetJSONKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case 'A':
			b.WriteString(`\u0041`)
		case '/':
			b.WriteString(`\/`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func tailnetStateWithField(t *testing.T, line, field string, extra map[string]json.RawMessage) []byte {
	t.Helper()
	base, err := json.Marshal(map[string]any{"installed": true, "keys": []string{line}})
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(base, &obj) != nil {
		t.Fatal(base)
	}
	if field != "" {
		obj[field] = json.RawMessage(`"x"`)
	}
	for k, v := range extra {
		obj[k] = v
	}
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func serveTailnetRaw(t *testing.T, s *Server, raw []byte) {
	t.Helper()
	serveTailnetGuest(t, s, func(w http.ResponseWriter, _ tailnetGuestInput) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})
}

func TestTailnetKeyTopLevelFieldNames(t *testing.T) {
	line, body, _ := testAuthorizedKey(t, "top")
	escaped := `{"installed":true,"keys":[` + string(mustJSON(t, line)) + `],"` + escapeTailnetJSONKey(body) + `":"x"}`
	named := tailnetStateWithField(t, line, body, nil)
	collision := tailnetStateWithField(t, line, body, map[string]json.RawMessage{hiddenTailnetKey: json.RawMessage(`"y"`)})

	t.Run("body GET", func(t *testing.T) {
		s := testServer(t)
		serveTailnetRaw(t, s, named)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
		if !bytes.Contains(w.Body.Bytes(), []byte(hiddenTailnetKey)) {
			t.Fatal(w.Body.String())
		}
		_ = decodeSSHKeys(t, w.Body.Bytes())
	})
	t.Run("body agent", func(t *testing.T) {
		s := agentTestController(t)
		serveTailnetRaw(t, s, named)
		data, err := AgentCall(context.Background(), s.configPath, "tailscale.get", nil)
		if err != nil {
			t.Fatal(err)
		}
		assertNoMaterial(t, data, body)
		if !bytes.Contains(data, []byte(hiddenTailnetKey)) {
			t.Fatal(data)
		}
	})
	t.Run("escaped GET", func(t *testing.T) {
		s := testServer(t)
		serveTailnetRaw(t, s, []byte(escaped))
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
		_ = decodeSSHKeys(t, w.Body.Bytes())
	})
	t.Run("escaped agent", func(t *testing.T) {
		s := agentTestController(t)
		serveTailnetRaw(t, s, []byte(escaped))
		data, err := AgentCall(context.Background(), s.configPath, "tailscale.get", nil)
		if err != nil {
			t.Fatal(err)
		}
		assertNoMaterial(t, data, body)
	})
	t.Run("collision GET", func(t *testing.T) {
		s := testServer(t)
		serveTailnetRaw(t, s, collision)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 502 || !strings.Contains(w.Body.String(), "Tailscale 组件返回了无效状态") {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), body)
	})
	t.Run("collision agent", func(t *testing.T) {
		s := agentTestController(t)
		serveTailnetRaw(t, s, collision)
		data, err := AgentCall(context.Background(), s.configPath, "tailscale.get", nil)
		if err == nil {
			t.Fatal(data)
		}
		var ae *AgentError
		if !errors.As(err, &ae) {
			t.Fatal(err)
		}
		assertNoMaterial(t, []byte(ae.Message), body)
		assertNoMaterial(t, data, body)
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTailnetKeyRevealLocked(t *testing.T) {
	s := testServer(t)
	s.account = newTestAccount(t)
	var called atomic.Bool
	serveTailnetGuest(t, s, func(w http.ResponseWriter, _ tailnetGuestInput) {
		called.Store(true)
		writeTailnetGuestJSON(w, map[string]any{"installed": true, "keys": []string{}})
	})
	s.account.lock()
	w := request(s, "POST", "/api/tailscale/reveal-key", s.origin, `{"id":"SHA256:test","account_password":"initial-test-password"}`, true)
	if w.Code != http.StatusLocked {
		t.Fatal(w.Code, w.Body.String())
	}
	if called.Load() {
		t.Fatal("guest called while locked")
	}
}

func TestTailnetKeyRevealSharesVaultRateLimit(t *testing.T) {
	s := testServer(t)
	s.account = newTestAccount(t)
	save := `{"action":"save","entry":{"origin":"https://mail.example.com","username":"alice@example.com","password":"mail-secret"}}`
	if w := request(s, "POST", "/api/vault", s.origin, save, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	list := request(s, "GET", "/api/vault", s.origin, "", true)
	var db vaultData
	if json.Unmarshal(list.Body.Bytes(), &db) != nil || len(db.Entries) != 1 {
		t.Fatal(list.Body.String())
	}
	w := request(s, "POST", "/api/tailscale/reveal-key", s.origin, `{"id":"SHA256:test","account_password":"wrong"}`, true)
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	b, _ := json.Marshal(map[string]string{"action": "reveal", "id": db.Entries[0].ID, "account_password": "initial-test-password"})
	w = request(s, "POST", "/api/vault", s.origin, string(b), true)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "请稍后再试") {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "mail-secret") {
		t.Fatal("vault reveal leaked password")
	}
}

func tailnetStateWithNested(t *testing.T, lines []string, nested map[string]any) []byte {
	t.Helper()
	out, err := json.Marshal(map[string]any{"installed": true, "keys": lines, "meta": nested})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTailnetKeyNestedFieldNames(t *testing.T) {
	line1, body1, _ := testAuthorizedKey(t, "a")
	line2, body2, _ := testAuthorizedKey(t, "b")
	twoBodies := tailnetStateWithNested(t, []string{line1, line2}, map[string]any{body1: "keep-a", body2: "keep-b"})
	withHidden := tailnetStateWithNested(t, []string{line1}, map[string]any{body1: "keep-a", hiddenTailnetKey: "keep-hidden"})
	single := tailnetStateWithNested(t, []string{line1}, map[string]any{body1: "keep-value", "other": "ok"})

	assert502 := func(t *testing.T, raw []byte, materials ...string) {
		t.Helper()
		s := testServer(t)
		serveTailnetRaw(t, s, raw)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 502 || !strings.Contains(w.Body.String(), "Tailscale 组件返回了无效状态") {
			t.Fatal(w.Code, w.Body.String())
		}
		assertNoMaterial(t, w.Body.Bytes(), materials...)
	}
	assertAgent502 := func(t *testing.T, raw []byte, materials ...string) {
		t.Helper()
		s := agentTestController(t)
		serveTailnetRaw(t, s, raw)
		data, err := AgentCall(context.Background(), s.configPath, "tailscale.get", nil)
		if err == nil {
			t.Fatal(data)
		}
		var ae *AgentError
		if !errors.As(err, &ae) {
			t.Fatal(err)
		}
		assertNoMaterial(t, []byte(ae.Message), materials...)
		assertNoMaterial(t, data, materials...)
	}
	assertOK := func(t *testing.T, body []byte) {
		t.Helper()
		assertNoMaterial(t, body, body1)
		var obj map[string]json.RawMessage
		if json.Unmarshal(body, &obj) != nil {
			t.Fatal(body)
		}
		var meta map[string]any
		if json.Unmarshal(obj["meta"], &meta) != nil {
			t.Fatal(obj["meta"])
		}
		if _, ok := meta[body1]; ok {
			t.Fatal("nested key leaked")
		}
		if meta[hiddenTailnetKey] != "keep-value" || meta["other"] != "ok" {
			t.Fatalf("%#v", meta)
		}
	}

	t.Run("two bodies GET", func(t *testing.T) { assert502(t, twoBodies, body1, body2) })
	t.Run("two bodies agent", func(t *testing.T) { assertAgent502(t, twoBodies, body1, body2) })
	t.Run("collision GET", func(t *testing.T) { assert502(t, withHidden, body1) })
	t.Run("collision agent", func(t *testing.T) { assertAgent502(t, withHidden, body1) })
	t.Run("single GET", func(t *testing.T) {
		s := testServer(t)
		serveTailnetRaw(t, s, single)
		w := request(s, "GET", "/api/tailscale", s.origin, "", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		assertOK(t, w.Body.Bytes())
		_ = decodeSSHKeys(t, w.Body.Bytes())
	})
	t.Run("single agent", func(t *testing.T) {
		s := agentTestController(t)
		serveTailnetRaw(t, s, single)
		data, err := AgentCall(context.Background(), s.configPath, "tailscale.get", nil)
		if err != nil {
			t.Fatal(err)
		}
		assertOK(t, data)
	})
}
