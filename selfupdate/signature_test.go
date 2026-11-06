package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
)

func withReleaseKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, oldRepo := PublicKey, Repo
	PublicKey, Repo = base64.StdEncoding.EncodeToString(pub), "example/artex"
	t.Cleanup(func() { PublicKey, Repo = oldKey, oldRepo })
	return priv
}

func TestUpdatesAreDisabledUnlessBuildConfiguresThem(t *testing.T) {
	if Enabled() {
		t.Fatal("a default build must not update from anywhere")
	}
	withReleaseKey(t)
	if !Enabled() {
		t.Fatal("repo and key configured")
	}
	Repo = ""
	if Enabled() {
		t.Fatal("key without a repo is not enough")
	}
}

func TestVerifySums(t *testing.T) {
	priv := withReleaseKey(t)
	sums := []byte("abc  artex.zip\n")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums))

	if err := verifySums(sums, []byte(sig+"\n")); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := verifySums([]byte("evil  artex.zip\n"), []byte(sig)); err == nil {
		t.Fatal("tampered checksums accepted")
	}
	if err := verifySums(sums, []byte("not base64!")); err == nil {
		t.Fatal("malformed signature accepted")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifySums(sums, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(other, sums)))); err == nil {
		t.Fatal("signature from another key accepted")
	}
}

type assetTransport map[string]string

func (a assetTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, ok := a[r.URL.Path]
	if !ok {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func TestFetchSumsRequiresSignature(t *testing.T) {
	priv := withReleaseKey(t)
	const sums = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  artex.zip\n"
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(sums)))
	const base = "https://github.com"
	client := &http.Client{Transport: assetTransport{"/sums": sums, "/sums.sig": sig, "/bad.sig": base64.StdEncoding.EncodeToString(make([]byte, 64))}}
	ctx := context.Background()
	sumsEntry := Asset{Name: sumsAsset, URL: base + "/sums"}

	if _, err := fetchSums(ctx, client, &Release{Assets: []Asset{sumsEntry}}); err == nil || !strings.Contains(err.Error(), sumsSigAsset) {
		t.Fatalf("release without a signature: err=%v", err)
	}
	if _, err := fetchSums(ctx, client, &Release{Assets: []Asset{sumsEntry, {Name: sumsSigAsset, URL: base + "/bad.sig"}}}); err == nil {
		t.Fatal("wrong signature accepted")
	}
	got, err := fetchSums(ctx, client, &Release{Assets: []Asset{sumsEntry, {Name: sumsSigAsset, URL: base + "/sums.sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got["artex.zip"] == "" {
		t.Fatalf("sums=%v", got)
	}
}
