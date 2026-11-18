package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
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

func TestInheritedTailnetEnvClearsControlURL(t *testing.T) {
	if !strings.Contains(strings.Join(inheritedTailnetEnv(), ","), "TS_CONTROL_URL") {
		t.Fatal("TS_CONTROL_URL must be cleared")
	}
	t.Setenv("TS_CONTROL_URL", "https://evil.example")
	clearInheritedTailnetEnv()
	if os.Getenv("TS_CONTROL_URL") != "" {
		t.Fatal("TS_CONTROL_URL still set")
	}
}

func TestOfficialStateDirDoesNotCreateServers(t *testing.T) {
	n, err := newNode(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if n.stateDir() != n.dir {
		t.Fatal(n.stateDir())
	}
	if _, err := os.Stat(filepath.Join(n.dir, "servers")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestUseControlURLRejectsInvalidAndKeepsState(t *testing.T) {
	n, err := newNode(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n.config.ControlURL = "https://hs.example.com"
	if err := n.useControlURL("http://hs.example.com"); err == nil {
		t.Fatal("accepted http")
	}
	if n.config.ControlURL != "https://hs.example.com" {
		t.Fatal(n.config.ControlURL)
	}
}

func TestPersistedInvalidControlURLDoesNotStart(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"enabled":true,"control_url":"http://hs.example.com"}`), 0600); err != nil {
		t.Fatal(err)
	}
	n, err := newNode(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !n.config.Enabled || n.config.ControlURL != "http://hs.example.com" {
		t.Fatalf("%+v", n.config)
	}
	if err := n.start(); err == nil || n.server != nil || n.startError == "" {
		t.Fatalf("started invalid control url: server=%v err=%v startError=%q", n.server, err, n.startError)
	}
	st, err := n.snapshot(context.Background())
	if err != nil || st.ControlURL != "http://hs.example.com" {
		t.Fatalf("%+v %v", st, err)
	}
	if !strings.Contains(strings.Join(st.Health, "\n"), "已保存的控制服务器地址无效") {
		t.Fatal(st.Health)
	}
	n.config.Enabled = false
	if err := n.useControlURL(""); err != nil {
		t.Fatal(err)
	}
	if n.config.ControlURL != "" || n.invalidControl {
		t.Fatalf("%+v invalid=%v", n.config, n.invalidControl)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"enabled":true,"control_url":"https://hs.example.com/headscale"}`), 0600); err != nil {
		t.Fatal(err)
	}
	n, err = newNode(dir)
	if err != nil {
		t.Fatal(err)
	}
	next := "https://hs.example.com"
	sum := sha256.Sum256([]byte(next))
	if err := os.MkdirAll(filepath.Join(n.dir, "servers"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(n.dir, "servers", hex.EncodeToString(sum[:])), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := n.start(); err == nil || n.server != nil {
		t.Fatal("started with path in control url")
	}
	if err := n.useControlURL(next); err != nil {
		t.Fatal(err)
	}
	if n.config.ControlURL != next || n.invalidControl || n.server != nil {
		t.Fatalf("%+v invalid=%v server=%v", n.config, n.invalidControl, n.server)
	}
	st, err = n.snapshot(context.Background())
	if err != nil || st.ControlURL != next {
		t.Fatalf("%+v %v", st, err)
	}
	if strings.Contains(strings.Join(st.Health, "\n"), "已保存的控制服务器地址无效") {
		t.Fatal(st.Health)
	}
}

func TestPersistedControlURLIsNormalized(t *testing.T) {
	for _, c := range []struct{ raw, want string }{
		{"HTTPS://Headscale.Example.COM:443/", "https://headscale.example.com"},
		{"https://[2001:DB8::1]:443/", "https://[2001:db8::1]"},
	} {
		dir := t.TempDir()
		b, err := json.Marshal(settings{ControlURL: c.raw})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "settings.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
		n, err := newNode(dir)
		if err != nil {
			t.Fatal(err)
		}
		if n.config.ControlURL != c.want || n.invalidControl {
			t.Fatalf("%q: got %q invalid=%v", c.raw, n.config.ControlURL, n.invalidControl)
		}
		sum := sha256.Sum256([]byte(c.want))
		if n.stateDir() != filepath.Join(n.dir, "servers", hex.EncodeToString(sum[:])) {
			t.Fatal(n.stateDir())
		}
	}
}

func TestSwitchControlURLNoopWhenUnchanged(t *testing.T) {
	n, err := newNode(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n.config.ControlURL = "https://hs.example.com"
	if err := n.switchControlURL("https://hs.example.com"); err != nil {
		t.Fatal(err)
	}
	if n.server != nil {
		t.Fatal("noop started a server")
	}
}

func TestSwitchControlURLSaveFailureRollsBack(t *testing.T) {
	n, err := newNode(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n.config.ControlURL = "https://old.example.com"
	if err := n.save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(n.dir, "settings.json.tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := n.switchControlURL("https://new.example.com"); err == nil {
		t.Fatal("save should fail")
	}
	if n.config.ControlURL != "https://old.example.com" {
		t.Fatal(n.config.ControlURL)
	}
}

func TestSwitchControlURLStartFailureKeepsHealth(t *testing.T) {
	n, err := newNode(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n.config.Enabled = true
	next := "https://hs.example.com"
	sum := sha256.Sum256([]byte(next))
	if err := os.MkdirAll(filepath.Join(n.dir, "servers"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(n.dir, "servers", hex.EncodeToString(sum[:])), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := n.switchControlURL(next); err != nil {
		t.Fatal(err)
	}
	st, err := n.snapshot(context.Background())
	if err != nil || st.ControlURL != next || st.Backend != "Stopped" {
		t.Fatalf("%+v %v", st, err)
	}
	if !strings.Contains(strings.Join(st.Health, "\n"), "Tailscale 未能启动：") {
		t.Fatal(st.Health)
	}
	again, err := n.snapshot(context.Background())
	if err != nil || !strings.Contains(strings.Join(again.Health, "\n"), "Tailscale 未能启动：") {
		t.Fatal(again.Health, err)
	}
	if _, err := n.run(context.Background(), request{Action: "disconnect"}); err != nil {
		t.Fatal(err)
	}
	cleared, err := n.snapshot(context.Background())
	if err != nil || strings.Contains(strings.Join(cleared.Health, "\n"), "未能启动") {
		t.Fatal(cleared.Health, err)
	}
}

func TestControlURLPersistsAndStatusDoesNotSwitch(t *testing.T) {
	dir := t.TempDir()
	n, err := newNode(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.switchControlURL("https://hs.example.com"); err != nil {
		t.Fatal(err)
	}
	st, err := n.run(context.Background(), request{Action: "status"})
	if err != nil || st.ControlURL != "https://hs.example.com" {
		t.Fatalf("%+v %v", st, err)
	}
	saved, err := newNode(dir)
	if err != nil || saved.config.ControlURL != "https://hs.example.com" {
		t.Fatalf("%+v %v", saved, err)
	}
	if _, err := n.run(context.Background(), request{Action: "disconnect"}); err != nil {
		t.Fatal(err)
	}
	if n.config.ControlURL != "https://hs.example.com" || n.config.Enabled {
		t.Fatalf("%+v", n.config)
	}
}

func TestControlServerRequiresURL(t *testing.T) {
	n, err := newNode(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.run(context.Background(), request{Action: "control-server"}); err == nil {
		t.Fatal("missing control_url")
	}
}

func machineKeyFromDir(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "tailscaled.state"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		t.Fatalf("state: %s", b)
	}
	for _, key := range []string{"_machinekey", "machinekey"} {
		if v, ok := m[key]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil && s != "" {
				return s
			}
		}
	}
	t.Fatalf("no machine key in %s", b)
	return ""
}

func startTestControl(t *testing.T, derp *tailcfg.DERPMap) *httptest.Server {
	t.Helper()
	control := &testcontrol.Server{DERPMap: derp, MagicDNSDomain: "cage-test.ts.net", DNSConfig: &tailcfg.DNSConfig{Proxied: true}, Logf: logger.Discard}
	server := httptest.NewUnstartedServer(control)
	control.HTTPTestServer = server
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func TestSwitchControlURLIsolatesIdentity(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	t.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	envknob.SetenvForTest(t, "TS_DEBUG_ALWAYS_USE_DERP", "true")
	netns.SetEnabled(false)
	defer netns.SetEnabled(true)
	derp := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	a := startTestControl(t, derp)
	b := startTestControl(t, derp)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir := filepath.Join(t.TempDir(), "cage")
	n, err := newNode(dir)
	if err != nil {
		t.Fatal(err)
	}
	n.config.Enabled = true
	if err := n.switchControlURL(a.URL); err != nil {
		t.Fatal(err)
	}
	if n.server == nil {
		t.Fatal(n.startError)
	}
	stA, err := n.server.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dirA := n.stateDir()
	keyA := machineKeyFromDir(t, dirA)
	idA := stA.Self.ID
	if err := n.switchControlURL(b.URL); err != nil {
		t.Fatal(err)
	}
	if n.server == nil {
		t.Fatal(n.startError)
	}
	if _, err := n.server.Up(ctx); err != nil {
		t.Fatal(err)
	}
	dirB := n.stateDir()
	keyB := machineKeyFromDir(t, dirB)
	if dirA == dirB || keyA == keyB {
		t.Fatalf("identity leaked: %s %s %s %s", dirA, dirB, keyA, keyB)
	}
	if err := n.switchControlURL(a.URL); err != nil {
		t.Fatal(err)
	}
	restored, err := n.server.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Self.ID != idA || machineKeyFromDir(t, n.stateDir()) != keyA {
		t.Fatal("switch back replaced identity")
	}
	if _, err := n.run(ctx, request{Action: "disconnect"}); err != nil {
		t.Fatal(err)
	}
	if n.config.ControlURL != a.URL || n.config.Enabled {
		t.Fatalf("%+v", n.config)
	}
	n.config.Enabled = true
	if err := n.save(); err != nil {
		t.Fatal(err)
	}
	n.stop()
	restarted, err := newNode(dir)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.config.ControlURL != a.URL || !restarted.config.Enabled {
		t.Fatalf("%+v", restarted.config)
	}
	if !restarted.invalidControl {
		t.Fatal("http testcontrol should be rejected until switchControlURL")
	}
	if err := restarted.switchControlURL(a.URL); err != nil {
		t.Fatal(err)
	}
	if restarted.server == nil {
		t.Fatal(restarted.startError)
	}
	defer func() { restarted.mu.Lock(); restarted.stop(); restarted.mu.Unlock() }()
	again, err := restarted.server.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Self.ID != idA {
		t.Fatal("restart replaced identity")
	}
	if _, err := restarted.run(ctx, request{Action: "logout"}); err != nil {
		t.Fatal(err)
	}
	if restarted.config.ControlURL != a.URL {
		t.Fatal(restarted.config.ControlURL)
	}
}
