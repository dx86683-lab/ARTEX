//go:build !windows

package server

import (
	"os/exec"
	"syscall"
)

// killProcessGroupOnCancel starts c in a new process group and makes cancellation kill
// the whole group, so children that outlive the interpreter do not keep running.
func killProcessGroupOnCancel(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
}
