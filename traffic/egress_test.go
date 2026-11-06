package traffic

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyRefusesBlockedHostWithoutContactingIt(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "reached")
	}))
	defer target.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	go func() { _ = tr.Start() }()

	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	get := func() (int, string) {
		t.Helper()
		var resp *http.Response
		var err error
		for i := 0; i < 50; i++ { // the proxy goroutine may not be listening yet
			if resp, err = client.Get(target.URL); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	if code, body := get(); code != 200 || body != "reached" {
		t.Fatalf("without a gate: %d %q", code, body)
	}

	tr.SetEgressGate(func(host string) (bool, string) { return host == "127.0.0.1", "test rule" })
	before := hits.Load()
	code, body := get()
	if code != http.StatusForbidden || !strings.Contains(body, "test rule") {
		t.Fatalf("blocked host: %d %q", code, body)
	}
	if hits.Load() != before {
		t.Fatal("the proxy contacted a blocked host")
	}

	tr.SetEgressGate(nil)
	if code, _ := get(); code != 200 {
		t.Fatalf("after removing the gate: %d", code)
	}
}

func TestBlockedHostIsNotTunneledEvenWhenMarkedPassthrough(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.pass.Store("blocked.example", struct{}{})
	tr.pass.Store("other.example", struct{}{})
	tr.SetEgressGate(func(host string) (bool, string) { return host == "blocked.example", "r" })

	if !tr.shouldIntercept(&http.Request{Host: "blocked.example:443"}) {
		t.Fatal("a tunnel would skip the addon that refuses the request")
	}
	if tr.shouldIntercept(&http.Request{Host: "other.example:443"}) {
		t.Fatal("an unblocked passthrough host should stay tunneled")
	}
}
