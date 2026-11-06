package config

import (
	"os"
	"sync"
)

// sensitiveEnv lists the variables removed from the process environment at startup.
// Agent shells, Python tools and stdio MCP servers inherit os.Environ(), so anything
// left there is one `env` away from a prompt-injected worker.
var sensitiveEnv = []string{
	"ANTHROPIC_API_KEY",
	"OPENAI_API_KEY",
	"ARTEX_PG_DSN",
	"ARTEX_INIT_TOKEN",
	"ARTEX_LLM_PROXY",
	"POSTGRES_PASSWORD",
}

var (
	sealedMu sync.RWMutex
	sealed   = map[string]string{}
)

// SealSecrets moves sensitive variables from the environment into process memory.
// Call it once at the very start of main. It does not erase /proc/<pid>/environ, so
// it is not a boundary against code running under the same uid.
func SealSecrets() {
	sealedMu.Lock()
	defer sealedMu.Unlock()
	for _, name := range sensitiveEnv {
		if v, ok := os.LookupEnv(name); ok {
			sealed[name] = v
			_ = os.Unsetenv(name)
		}
	}
}

// Secret returns a sealed value, falling back to the live environment for anything
// not sealed (tests and tools that never call SealSecrets).
func Secret(name string) string {
	sealedMu.RLock()
	v, ok := sealed[name]
	sealedMu.RUnlock()
	if ok {
		return v
	}
	return os.Getenv(name)
}
