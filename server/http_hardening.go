package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	maxAuthBody = 64 << 10 // password routes are reachable without a token
	maxJSONBody = 64 << 20
	authBodyFor = 30 * time.Second

	loginFreeAttempts = 5
	loginBaseLock     = 30 * time.Second
	loginMaxLock      = 15 * time.Minute
	loginForgetAfter  = time.Hour
	loginMaxTracked   = 10000

	// Each bcrypt comparison burns tens of milliseconds of CPU, so concurrent checks
	// are capped independently of the per-client limit.
	maxConcurrentBcrypt = 4
)

var bcryptSlots = make(chan struct{}, maxConcurrentBcrypt)

// comparePassword runs bcrypt under the concurrency cap. The caller treats any error
// as a failed check, so an abandoned request fails closed.
func (s *Server) comparePassword(r *http.Request, hash, password string) error {
	select {
	case bcryptSlots <- struct{}{}:
		defer func() { <-bcryptSlots }()
	case <-r.Context().Done():
		return r.Context().Err()
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// clientIP uses the socket address only. X-Forwarded-For is client-controlled, and
// trusting it would let an attacker pick a fresh identity for every guess.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type loginAttempt struct {
	failures int
	lockedTo time.Time
	lastSeen time.Time
}

// loginLimiter applies exponential backoff per client. The zero value is ready to use.
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
	now      func() time.Time // test hook
}

func (l *loginLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *loginLimiter) check(ip string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[ip]
	if a == nil {
		return 0, false
	}
	if wait := a.lockedTo.Sub(l.clock()); wait > 0 {
		return wait, true
	}
	return 0, false
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	if l.attempts == nil {
		l.attempts = map[string]*loginAttempt{}
	}
	if len(l.attempts) >= loginMaxTracked {
		l.pruneLocked(now)
	}
	a := l.attempts[ip]
	if a == nil || now.Sub(a.lastSeen) > loginForgetAfter {
		a = &loginAttempt{}
		l.attempts[ip] = a
	}
	a.failures++
	a.lastSeen = now
	if over := a.failures - loginFreeAttempts; over >= 0 {
		lock := loginMaxLock
		if over < 10 && loginBaseLock<<over < loginMaxLock {
			lock = loginBaseLock << over
		}
		a.lockedTo = now.Add(lock)
	}
}

func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

// pruneLocked drops expired entries, then everything if an attacker cycling through
// addresses has filled the table with live ones; memory stays bounded either way.
func (l *loginLimiter) pruneLocked(now time.Time) {
	for ip, a := range l.attempts {
		if now.Sub(a.lastSeen) > loginForgetAfter && !a.lockedTo.After(now) {
			delete(l.attempts, ip)
		}
	}
	if len(l.attempts) >= loginMaxTracked {
		l.attempts = map[string]*loginAttempt{}
	}
}

func writeRateLimited(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, fmt.Sprintf("尝试次数过多，请 %d 秒后重试", secs))
}

// limitRequestBody caps API request bodies. Multipart handlers enforce their own,
// larger limits. Read deadlines apply to /api/auth/* only: a connection-level read
// deadline also cancels the request context when it fires, which would kill SSE.
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			if strings.HasPrefix(r.URL.Path, "/api/auth/") {
				r.Body = http.MaxBytesReader(w, r.Body, maxAuthBody)
				if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(authBodyFor)); err != nil && !errors.Is(err, http.ErrNotSupported) {
					writeErr(w, 500, err.Error())
					return
				}
			} else if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
				r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// webCSP restricts the frontend. 'unsafe-inline' is required by the static Next export
// (inline bootstrap scripts); connect-src 'self' is what stops an injected script from
// sending a stolen token elsewhere.
const webCSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; " +
	"object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Content-Security-Policy", webCSP)
		}
		next.ServeHTTP(w, r)
	})
}
