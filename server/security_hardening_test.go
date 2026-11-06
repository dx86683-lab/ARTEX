package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
)

func newAuthServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	removePassword(t, m.pg)
	t.Cleanup(func() { removePassword(t, m.pg) })
	s := &Server{m: m, jwtKey: []byte(strings.Repeat("k", 32)), initToken: "init-secret"}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/init", s.authInit)
	mux.HandleFunc("POST /api/auth/login", s.authLogin)
	mux.HandleFunc("POST /api/auth/change-password", s.authChangePassword)
	mux.HandleFunc("POST /api/sse-ticket", s.sseTicket)
	ok := func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) }
	mux.HandleFunc("GET /api/tasks", ok)
	mux.HandleFunc("GET /api/logs/stream", ok)
	return s, limitRequestBody(s.requireAuth(mux))
}

func removePassword(t *testing.T, pg *db.DB) {
	t.Helper()
	if _, err := pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey); err != nil {
		t.Fatal(err)
	}
}

func doJSON(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func tokenFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Token  string `json:"token"`
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	if out.Ticket != "" {
		return out.Ticket
	}
	return out.Token
}

func TestAuthInitRequiresInitToken(t *testing.T) {
	_, h := newAuthServer(t)
	for _, body := range []string{
		`{"password":"correct horse battery"}`,
		`{"password":"correct horse battery","init_token":"wrong"}`,
	} {
		if w := doJSON(h, "POST", "/api/auth/init", "", body); w.Code != 403 {
			t.Fatalf("%s: status=%d want 403; %s", body, w.Code, w.Body)
		}
	}
	w := doJSON(h, "POST", "/api/auth/init", "", `{"password":"correct horse battery","init_token":"init-secret"}`)
	if w.Code != 200 || tokenFrom(t, w) == "" {
		t.Fatalf("status=%d; %s", w.Code, w.Body)
	}
}

func TestAuthInitWithoutConfiguredTokenIsClosed(t *testing.T) {
	s, h := newAuthServer(t)
	s.initToken = ""
	if w := doJSON(h, "POST", "/api/auth/init", "", `{"password":"correct horse battery","init_token":""}`); w.Code != 403 {
		t.Fatalf("status=%d want 403", w.Code)
	}
}

func TestChangePasswordRevokesOlderTokens(t *testing.T) {
	_, h := newAuthServer(t)
	old := tokenFrom(t, doJSON(h, "POST", "/api/auth/init", "", `{"password":"first password","init_token":"init-secret"}`))
	if w := doJSON(h, "GET", "/api/tasks", old, ""); w.Code != 200 {
		t.Fatalf("fresh token rejected: %d %s", w.Code, w.Body)
	}
	ticket := tokenFrom(t, doJSON(h, "POST", "/api/sse-ticket", old, ""))

	w := doJSON(h, "POST", "/api/auth/change-password", old, `{"old_password":"first password","new_password":"second password"}`)
	if w.Code != 200 {
		t.Fatalf("change password: %d %s", w.Code, w.Body)
	}
	fresh := tokenFrom(t, w)

	if w := doJSON(h, "GET", "/api/tasks", old, ""); w.Code != 401 {
		t.Fatalf("old token still valid: %d", w.Code)
	}
	if w := doJSON(h, "GET", "/api/logs/stream?token="+ticket, "", ""); w.Code != 401 {
		t.Fatalf("old ticket still valid: %d", w.Code)
	}
	if w := doJSON(h, "GET", "/api/tasks", fresh, ""); w.Code != 200 {
		t.Fatalf("new token rejected: %d %s", w.Code, w.Body)
	}
}

func TestWrongOldPasswordDoesNotLogOut(t *testing.T) {
	_, h := newAuthServer(t)
	tok := tokenFrom(t, doJSON(h, "POST", "/api/auth/init", "", `{"password":"first password","init_token":"init-secret"}`))
	w := doJSON(h, "POST", "/api/auth/change-password", tok, `{"old_password":"nope nope","new_password":"second password"}`)
	if w.Code != 403 {
		t.Fatalf("status=%d want 403: the frontend treats 401 as session expired", w.Code)
	}
}

func TestSSETicketOnlyOpensStreams(t *testing.T) {
	_, h := newAuthServer(t)
	tok := tokenFrom(t, doJSON(h, "POST", "/api/auth/init", "", `{"password":"first password","init_token":"init-secret"}`))
	ticket := tokenFrom(t, doJSON(h, "POST", "/api/sse-ticket", tok, ""))

	if w := doJSON(h, "GET", "/api/logs/stream?token="+ticket, "", ""); w.Code != 200 {
		t.Fatalf("ticket refused on stream: %d %s", w.Code, w.Body)
	}
	if w := doJSON(h, "GET", "/api/tasks?token="+ticket, "", ""); w.Code != 401 {
		t.Fatalf("ticket accepted outside SSE: %d", w.Code)
	}
	if w := doJSON(h, "GET", "/api/tasks", ticket, ""); w.Code != 401 {
		t.Fatalf("ticket accepted as bearer: %d", w.Code)
	}
	if w := doJSON(h, "GET", "/api/logs/stream?token="+tok, "", ""); w.Code != 401 {
		t.Fatalf("session token accepted in URL: %d", w.Code)
	}
}

func TestAPIDoesNotAcceptCookieAuth(t *testing.T) {
	_, h := newAuthServer(t)
	tok := tokenFrom(t, doJSON(h, "POST", "/api/auth/init", "", `{"password":"first password","init_token":"init-secret"}`))
	r := httptest.NewRequest("GET", "/api/tasks", nil)
	r.AddCookie(&http.Cookie{Name: "artex_token", Value: tok})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("status=%d want 401: cookie auth would expose the API to cross-site requests", w.Code)
	}
}

func TestLoginBacksOffAfterRepeatedFailures(t *testing.T) {
	s, h := newAuthServer(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("right password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < loginFreeAttempts; i++ {
		if w := doJSON(h, "POST", "/api/auth/login", "", `{"username":"ARTEX","password":"wrong"}`); w.Code != 401 {
			t.Fatalf("attempt %d: status=%d", i, w.Code)
		}
	}
	w := doJSON(h, "POST", "/api/auth/login", "", `{"username":"ARTEX","password":"right password"}`)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("status=%d retry=%q; a locked client must not get a password check", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestLoginLimiterExpiresAndResets(t *testing.T) {
	now := time.Unix(1000, 0)
	l := &loginLimiter{now: func() time.Time { return now }}
	for i := 0; i < loginFreeAttempts; i++ {
		l.fail("a")
	}
	if _, limited := l.check("a"); !limited {
		t.Fatal("expected lock")
	}
	if _, limited := l.check("b"); limited {
		t.Fatal("lock leaked to another client")
	}
	now = now.Add(loginBaseLock + time.Second)
	if _, limited := l.check("a"); limited {
		t.Fatal("lock should expire")
	}
	l.fail("a") // sixth failure doubles the lock
	if wait, _ := l.check("a"); wait != 2*loginBaseLock {
		t.Fatalf("wait=%v", wait)
	}
	l.success("a")
	if _, limited := l.check("a"); limited {
		t.Fatal("success should clear the record")
	}
}

func TestLoginLimiterMemoryIsBounded(t *testing.T) {
	var l loginLimiter
	for i := 0; i < loginMaxTracked+100; i++ {
		l.fail(string(rune(0x4e00 + i)))
	}
	if len(l.attempts) > loginMaxTracked {
		t.Fatalf("tracked %d entries", len(l.attempts))
	}
}

func TestClientIPIgnoresForwardedFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r); got != "10.0.0.1" {
		t.Fatalf("clientIP=%q", got)
	}
}

func TestOversizedAuthBodyIsRejected(t *testing.T) {
	_, h := newAuthServer(t)
	huge := `{"username":"ARTEX","password":"` + strings.Repeat("a", maxAuthBody) + `"}`
	if w := doJSON(h, "POST", "/api/auth/login", "", huge); w.Code != 400 {
		t.Fatalf("status=%d want 400", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	page, api := httptest.NewRecorder(), httptest.NewRecorder()
	h.ServeHTTP(page, httptest.NewRequest("GET", "/login", nil))
	h.ServeHTTP(api, httptest.NewRequest("GET", "/api/health", nil))
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatalf("CSP=%q", page.Header().Get("Content-Security-Policy"))
	}
	if api.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("API responses need nosniff")
	}
}

func TestRenderTemplateDoesNotReexpandValues(t *testing.T) {
	params := map[string]any{"a": "{b}", "b": "; touch PWNED #"}
	// Map iteration order is random, so one pass could pass by luck.
	for i := 0; i < 200; i++ {
		got := renderTemplate("echo {a} {b}", params, shellQuote)
		if want := `echo '{b}' '; touch PWNED #'`; got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestRenderTemplateLeavesUnknownPlaceholders(t *testing.T) {
	if got := renderTemplate(`{"a":"{x}","b":{y}}`, map[string]any{"x": "1"}, identity); got != `{"a":"1","b":{y}}` {
		t.Fatalf("got %q", got)
	}
}

func TestRenderURLTemplateEscapesByPosition(t *testing.T) {
	params := map[string]any{"base": "https://h.example:8443", "p": "a/b c?x=1", "q": "1&admin=true"}
	got := renderURLTemplate("{base}/api/{p}?v={q}&keep={missing}", params)
	if want := "https://h.example:8443/api/a/b%20c%3Fx=1?v=1%26admin%3Dtrue&keep={missing}"; got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestExecPythonTimeoutIsNotHeldByChildren(t *testing.T) {
	interp := testPythonInterp(t)
	code := "import subprocess,time\nsubprocess.Popen(['sleep','30'])\ntime.sleep(30)\n"
	start := time.Now()
	body, err := execPython(t.Context(), interp, "hang", code, nil, t.TempDir(), nil, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("returned after %v; a child holding stdout must not extend the timeout", d)
	}
	if !strings.Contains(body, "超时") {
		t.Fatalf("body=%q", body)
	}
}

func TestExecPythonCapsOutput(t *testing.T) {
	interp := testPythonInterp(t)
	code := "import sys\nfor _ in range(30):\n    sys.stdout.write('x'*(1<<20))\n"
	body, err := execPython(t.Context(), interp, "big", code, nil, t.TempDir(), nil, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > maxToolOutput+1024 || !strings.Contains(body, "已截断") {
		t.Fatalf("len=%d truncated=%v", len(body), strings.Contains(body, "已截断"))
	}
}

func testPythonInterp(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("python not installed")
	return ""
}

// wsServer returns a server rooted at a temp dir with a secret file just outside it and
// a symlink inside pointing at that file.
func wsServer(t *testing.T) (s *Server, data, secret string) {
	t.Helper()
	base := t.TempDir()
	data = filepath.Join(base, "data")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	secret = filepath.Join(base, "secret")
	if err := os.WriteFile(secret, []byte("S3CRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(data, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(base, filepath.Join(data, "up")); err != nil {
		t.Fatal(err)
	}
	return &Server{m: &Manager{dir: data}}, data, secret
}

func TestWorkspaceDoesNotFollowSymlinksOutOfRoot(t *testing.T) {
	s, _, secret := wsServer(t)
	for name, handler := range map[string]http.HandlerFunc{
		"/api/workspace/read?path=link":     s.wsRead,
		"/api/workspace/download?path=link": s.wsDownload,
		"/api/workspace/list?path=up":       s.wsList,
	} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("GET", name, nil))
		if w.Code == 200 || strings.Contains(w.Body.String(), "S3CRET") || strings.Contains(w.Body.String(), `"secret"`) {
			t.Errorf("%s escaped the root: %d %s", name, w.Code, w.Body)
		}
	}

	w := httptest.NewRecorder()
	s.wsWrite(w, httptest.NewRequest("POST", "/api/workspace/write", strings.NewReader(`{"path":"link","content":"overwritten"}`)))
	if w.Code == 200 {
		t.Errorf("write through symlink succeeded: %s", w.Body)
	}
	if got, _ := os.ReadFile(secret); string(got) != "S3CRET" {
		t.Fatalf("file outside the root was modified: %q", got)
	}
}

func TestWorkspaceDeleteRemovesLinkNotTarget(t *testing.T) {
	s, data, secret := wsServer(t)
	w := httptest.NewRecorder()
	s.wsDelete(w, httptest.NewRequest("DELETE", "/api/workspace/delete?path=link", nil))
	if w.Code != 200 {
		t.Fatalf("status=%d %s", w.Code, w.Body)
	}
	if _, err := os.Lstat(filepath.Join(data, "link")); !os.IsNotExist(err) {
		t.Fatal("link should be gone")
	}
	if _, err := os.Stat(secret); err != nil {
		t.Fatal("target must survive")
	}
}

func TestWorkspaceRoundTripInsideRoot(t *testing.T) {
	s, _, _ := wsServer(t)
	w := httptest.NewRecorder()
	s.wsWrite(w, httptest.NewRequest("POST", "/x", strings.NewReader(`{"path":"a/b.txt","content":"hello"}`)))
	if w.Code != 200 {
		t.Fatalf("write: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	s.wsRead(w, httptest.NewRequest("GET", "/x?path=a/b.txt", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "hello") {
		t.Fatalf("read: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	s.wsDownload(w, httptest.NewRequest("GET", "/x?path=a/b.txt", nil))
	if w.Code != 200 || w.Body.String() != "hello" {
		t.Fatalf("download: %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	s.wsList(w, httptest.NewRequest("GET", "/x?path=", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"a"`) {
		t.Fatalf("list root: %d %s", w.Code, w.Body)
	}
}

func multipartUpload(t *testing.T, target string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("payload"))
	_ = mw.Close()
	r := httptest.NewRequest("POST", target, &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func TestUploadCannotBeRedirectedBySymlink(t *testing.T) {
	s, data, _ := wsServer(t)
	outside := filepath.Dir(data)

	w := httptest.NewRecorder()
	s.wsUpload(w, multipartUpload(t, "/api/workspace/upload?path=up"))
	if w.Code == 200 {
		t.Errorf("upload through directory symlink succeeded: %s", w.Body)
	}

	// An agent controls its own CWD, so it can plant the uploads directory as a link.
	if err := os.MkdirAll(filepath.Join(data, "drafts", "d1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(data, "drafts", "d1", "uploads")); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.chatUpload(w, multipartUpload(t, "/api/chat/upload?scope=staging&id=d1"))
	if w.Code == 200 {
		t.Errorf("chat upload through symlink succeeded: %s", w.Body)
	}
	if _, err := os.Stat(filepath.Join(outside, "note.txt")); err == nil {
		t.Fatal("upload landed outside the work dir")
	}
}

func TestMCPEnvMaskRoundTrip(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	name := "mask-test-" + time.Now().Format("150405.000000000")
	id, err := m.pg.SaveMCP(&db.MCPServer{Name: name, Transport: "http", URL: "https://mcp.invalid",
		Env: json.RawMessage(`{"X-API-Key":"real-secret","Empty":""}`)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteMCP(id) })

	w := httptest.NewRecorder()
	s.pgListMCP(w, httptest.NewRequest("GET", "/api/mcp", nil))
	if strings.Contains(w.Body.String(), "real-secret") {
		t.Fatal("GET /api/mcp leaked the credential")
	}
	if !strings.Contains(w.Body.String(), "X-API-Key") {
		t.Fatal("key names should stay visible")
	}

	stored := func() map[string]string {
		all, err := m.pg.ListMCP()
		if err != nil {
			t.Fatal(err)
		}
		for _, srv := range all {
			if srv.ID == id {
				return decodeStrMap(srv.Env)
			}
		}
		t.Fatal("server missing")
		return nil
	}

	// Saving the masked form back must keep the secret...
	got := s.restoreMCPEnv(id, maskMCPEnv(json.RawMessage(`{"X-API-Key":"real-secret","Empty":""}`)))
	if decodeStrMap(got)["X-API-Key"] != stored()["X-API-Key"] {
		t.Fatalf("restore lost the secret: %s", got)
	}
	// ...and a typed value must replace it.
	got = s.restoreMCPEnv(id, json.RawMessage(`{"X-API-Key":"new-secret"}`))
	if decodeStrMap(got)["X-API-Key"] != "new-secret" {
		t.Fatalf("typed value not kept: %s", got)
	}
}

func TestEgressGateAppliesGlobalBlockRules(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	rule, err := m.pg.CreateAssetInterceptRule("exact_domain", "egress-blocked.example", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteAssetInterceptRule(rule.ID) })

	gate := newEgressGate(m.pg)
	if blocked, reason := gate("egress-blocked.example"); !blocked || reason == "" {
		t.Fatalf("blocked=%v reason=%q", blocked, reason)
	}
	if blocked, _ := gate("allowed.example"); blocked {
		t.Fatal("unrelated host blocked")
	}
}
