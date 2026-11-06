//go:build windows

package server

import "os/exec"

// killProcessGroupOnCancel is a no-op on Windows: exec.CommandContext kills the direct
// child, and WaitDelay still bounds the wait for any descendant holding the pipes.
func killProcessGroupOnCancel(*exec.Cmd) {}
