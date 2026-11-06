package config

import (
	"os"
	"testing"
)

func TestSealSecretsRemovesValueFromEnvironmentButKeepsItReadable(t *testing.T) {
	// SealSecrets touches every listed variable, so register all of them for restore.
	for _, name := range sensitiveEnv {
		t.Setenv(name, "value-of-"+name)
	}
	t.Setenv("OPENAI_API_KEY", "sk-test")
	t.Cleanup(func() {
		sealedMu.Lock()
		sealed = map[string]string{}
		sealedMu.Unlock()
	})

	SealSecrets()

	if _, ok := os.LookupEnv("OPENAI_API_KEY"); ok {
		t.Fatal("sealed variable must not stay in the environment inherited by child processes")
	}
	if got := Secret("OPENAI_API_KEY"); got != "sk-test" {
		t.Fatalf("Secret()=%q", got)
	}
}

func TestSecretFallsBackToEnvironment(t *testing.T) {
	t.Setenv("ARTEX_PG_DSN", "postgres://unsealed")
	if got := Secret("ARTEX_PG_DSN"); got != "postgres://unsealed" {
		t.Fatalf("Secret()=%q", got)
	}
}
