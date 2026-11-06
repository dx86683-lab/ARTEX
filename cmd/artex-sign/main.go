// Command artex-sign creates the release signing key and signs SHA256SUMS. Keep the
// private key off GitHub: the signature only helps if a stolen release account cannot
// also produce one.
//
//	artex-sign keygen <private-key-file>       prints the public key for ARTEX_UPDATE_PUBKEY
//	artex-sign sign <private-key-file> <file>  writes <file>.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "artex-sign:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	switch {
	case len(args) == 2 && args[0] == "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		// O_EXCL: overwriting a release key would orphan every install that trusts it.
		f, err := os.OpenFile(args[1], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n"); err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
		return nil
	case len(args) == 3 && args[0] == "sign":
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(priv) != ed25519.PrivateKeySize {
			return fmt.Errorf("%s is not a valid private key", args[1])
		}
		msg, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		sig := ed25519.Sign(ed25519.PrivateKey(priv), msg)
		return os.WriteFile(args[2]+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
	}
	return fmt.Errorf("usage: artex-sign keygen <key-file> | artex-sign sign <key-file> <file>")
}
