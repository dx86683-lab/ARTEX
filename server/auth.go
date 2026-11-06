package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/config"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	jwtTTL         = 7 * 24 * time.Hour
	sseAudience    = "sse"
	sseTicketTTL   = 24 * time.Hour
	pwvCacheTTL    = 10 * time.Second
	initTokenEnv   = "ARTEX_INIT_TOKEN"
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// authClaims carries the password fingerprint that ties a session to the password
// it was issued under, so changing the password revokes every older token.
type authClaims struct {
	jwt.RegisteredClaims
	PWV string `json:"pwv,omitempty"`
}

// passwordFingerprint derives the claim from the stored hash. It is an HMAC rather
// than the hash itself because JWT payloads are readable by whoever holds the token.
func passwordFingerprint(key []byte, hash string) string {
	if hash == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(hash))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

func signClaims(key []byte, pwv string, ttl time.Duration, audience ...string) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, authClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "ARTEX",
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		PWV: pwv,
	}).SignedString(key)
}

// signJWT issues a session token that is only valid while no password is set.
// Handlers use signSession; this form remains for callers with no password context.
func signJWT(key []byte) (string, error) { return signClaims(key, "", jwtTTL) }

// signSession issues a 7-day session token bound to the current password.
func (s *Server) signSession(passwordHash string) (string, error) {
	return signClaims(s.jwtKey, passwordFingerprint(s.jwtKey, passwordHash), jwtTTL)
}

// parseToken validates signature, algorithm and expiry.
func parseToken(tokenStr string, key []byte) (*authClaims, bool) {
	claims := &authClaims{}
	t, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || !t.Valid {
		return nil, false
	}
	return claims, true
}

func (c *authClaims) isSSETicket() bool {
	for _, aud := range c.Audience {
		if aud == sseAudience {
			return true
		}
	}
	return false
}

// currentPWV returns the fingerprint of the stored password, cached briefly because
// it is checked on every API request. reset-password.sh edits the database directly,
// so the cache must expire rather than rely on an explicit invalidation. A transient
// read failure keeps the last known value: answering 401 would log the operator out.
func (s *Server) currentPWV() (string, error) {
	s.pwvMu.Lock()
	defer s.pwvMu.Unlock()
	if s.pwvLoaded && time.Since(s.pwvAt) < pwvCacheTTL {
		return s.pwvValue, nil
	}
	if s.m == nil || s.m.pg == nil {
		return "", nil
	}
	hash, _, err := s.m.pg.GetSetting(authPassKey)
	if err != nil {
		if s.pwvLoaded {
			return s.pwvValue, nil
		}
		return "", err
	}
	s.pwvValue, s.pwvLoaded, s.pwvAt = passwordFingerprint(s.jwtKey, hash), true, time.Now()
	return s.pwvValue, nil
}

func (s *Server) invalidatePWV() {
	s.pwvMu.Lock()
	s.pwvLoaded = false
	s.pwvMu.Unlock()
}

// authenticate checks a bearer session token against the current password.
func (s *Server) authenticate(tok string) (ok bool, unavailable bool) {
	claims, valid := parseToken(tok, s.jwtKey)
	if !valid || claims.isSSETicket() {
		return false, false
	}
	return s.claimsCurrent(claims)
}

func (s *Server) claimsCurrent(claims *authClaims) (ok bool, unavailable bool) {
	pwv, err := s.currentPWV()
	if err != nil {
		return false, true
	}
	return claims.PWV == pwv, false
}

func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// isSSEPath lists the only routes that accept a query-string ticket: EventSource
// cannot set headers, and everything else must not put credentials in a URL.
func isSSEPath(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		(strings.HasSuffix(r.URL.Path, "/stream") || strings.HasSuffix(r.URL.Path, "/events"))
}

// requireAuth wraps h with JWT validation.
// /api/auth/* and /api/health are exempt. Cookies are deliberately not accepted, which
// is what keeps the API out of reach of cross-site requests despite the open CORS.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		var ok, unavailable bool
		if tok := bearerToken(r); tok != "" {
			ok, unavailable = s.authenticate(tok)
		} else if ticket := r.URL.Query().Get("token"); ticket != "" && isSSEPath(r) {
			if claims, valid := parseToken(ticket, s.jwtKey); valid && claims.isSSETicket() {
				ok, unavailable = s.claimsCurrent(claims)
			}
		} else {
			writeErr(w, 401, "未授权")
			return
		}
		if unavailable {
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		if !ok {
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// POST /api/sse-ticket — exchanges the session for a read-scoped streaming ticket.
// Tickets go into URLs and therefore into reverse-proxy logs, so they only open SSE
// routes and expire within a day; they cannot call any other endpoint.
func (s *Server) sseTicket(w http.ResponseWriter, r *http.Request) {
	pwv, err := s.currentPWV()
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	ticket, err := signClaims(s.jwtKey, pwv, sseTicketTTL, sseAudience)
	if err != nil {
		writeErr(w, 500, "ticket 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"ticket": ticket, "expires_in": int(sseTicketTTL.Seconds())})
}

// prepareInitToken decides who may claim an uninitialised install. Without it the
// first visitor to reach the port becomes administrator, and an administrator can run
// arbitrary commands. The generated value only reaches the server log.
func (s *Server) prepareInitToken() {
	if tok := strings.TrimSpace(config.Secret(initTokenEnv)); tok != "" {
		s.initToken = tok
		return
	}
	if s.m != nil && s.m.pg != nil {
		if hash, _, err := s.m.pg.GetSetting(authPassKey); err == nil && hash != "" {
			return
		}
	}
	buf := make([]byte, 24)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			log.Fatalf("[auth] 生成初始化令牌失败: %v", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	s.initToken = string(buf)
	log.Printf("[auth] 管理员密码尚未设置。初始化令牌（在 /setup 页面填写）: %s", s.initToken)
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != "", "init_token_required": hash == ""})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "密码已设置")
		return
	}
	ip := clientIP(r)
	if wait, limited := s.authLimit.check(ip); limited {
		writeRateLimited(w, wait)
		return
	}
	var req struct {
		Password  string `json:"password"`
		InitToken string `json:"init_token"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if s.initToken == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.InitToken)), []byte(s.initToken)) != 1 {
		s.authLimit.fail(ip)
		writeErr(w, 403, "初始化令牌错误（见服务端启动日志）")
		return
	}
	if req.Password == "" {
		writeErr(w, 400, "密码不能为空")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "密码已设置")
		return
	}
	s.authLimit.success(ip)
	s.invalidatePWV()
	tok, err := s.signSession(string(hash))
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ok, unavailable := s.authenticate(bearerToken(r))
	if unavailable {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok {
		writeErr(w, 401, "未授权")
		return
	}
	ip := clientIP(r)
	if wait, limited := s.authLimit.check(ip); limited {
		writeRateLimited(w, wait)
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := s.comparePassword(r, hash, req.OldPassword); err != nil {
		s.authLimit.fail(ip)
		// 不能回 401：前端的 http() 见到 401 就清掉登录态跳回登录页。
		writeErr(w, 403, "当前密码错误")
		return
	}
	s.authLimit.success(ip)
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	s.invalidatePWV()
	// 旧 token 随改密一起失效，所以把新 token 交给发起改密的这个会话。
	tok, err := s.signSession(string(newHash))
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "token": tok})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ip := clientIP(r)
	if wait, limited := s.authLimit.check(ip); limited {
		writeRateLimited(w, wait)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.Username != "ARTEX" {
		s.authLimit.fail(ip)
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := s.comparePassword(r, hash, req.Password); err != nil {
		s.authLimit.fail(ip)
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	s.authLimit.success(ip)
	tok, err := s.signSession(hash)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
