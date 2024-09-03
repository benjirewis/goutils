//go:build linux || darwin

package pexec

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/pkg/errors"
)

func sigStr(sig syscall.Signal) string {
	//nolint:exhaustive
	switch sig {
	case syscall.SIGHUP:
		return "SIGHUP"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGQUIT:
		return "SIGQUIT"
	case syscall.SIGABRT:
		return "SIGABRT"
	case syscall.SIGUSR1:
		return "SIGUSR1"
	case syscall.SIGUSR2:
		return "SIGUSR2"
	case syscall.SIGTERM:
		return "SIGTERM"
	default:
		return "<UNKNOWN>"
	}
}

var knownSignals = []syscall.Signal{
	syscall.SIGHUP,
	syscall.SIGINT,
	syscall.SIGQUIT,
	syscall.SIGABRT,
	syscall.SIGUSR1,
	syscall.SIGUSR2,
	syscall.SIGTERM,
}

func parseSignal(sigStr, name string) (syscall.Signal, error) {
	switch sigStr {
	case "":
		return 0, nil
	case "HUP", "SIGHUP", "hangup", "1":
		return syscall.SIGHUP, nil
	case "INT", "SIGINT", "interrupt", "2":
		return syscall.SIGINT, nil
	case "QUIT", "SIGQUIT", "quit", "3":
		return syscall.SIGQUIT, nil
	case "ABRT", "SIGABRT", "aborted", "abort", "6":
		return syscall.SIGABRT, nil
	case "KILL", "SIGKILL", "killed", "kill", "9":
		return syscall.SIGKILL, nil
	case "TERM", "SIGTERM", "terminated", "terminate", "15":
		return syscall.SIGTERM, nil
	default:
		return 0, errors.Errorf("unknown %q name", sigStr)
	}
}

func (p *managedProcess) sysProcAttr() (*syscall.SysProcAttr, error) {
	attrs := &syscall.SysProcAttr{Setpgid: true}
	if len(p.username) > 0 {
		user, err := user.Lookup(p.username)
		if err != nil {
			return nil, err
		}
		val, err := strconv.ParseUint(user.Uid, 10, 32)
		if err != nil {
			return nil, err
		}
		attrs.Credential = &syscall.Credential{}
		attrs.Credential.Uid = uint32(val)
		val, err = strconv.ParseUint(user.Gid, 10, 32)
		if err != nil {
			return nil, err
		}
		attrs.Credential.Gid = uint32(val)
	}
	return attrs, nil
}

func (p *managedProcess) kill() (bool, error) {
	p.logger.Infof("stopping process %d with signal %s", p.cmd.Process.Pid, p.stopSig)
	// First let's try to directly signal the process.
	if err := p.cmd.Process.Signal(p.stopSig); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return false, errors.Wrapf(err, "error signaling process %d with signal %s", p.cmd.Process.Pid, p.stopSig)
	}

	// In case the process didn't stop, or left behind any orphan children in its process group,
	// we now send a signal to everything in the process group after a brief wait.
	timer := time.NewTimer(p.stopWaitInterval)
	defer timer.Stop()
	select {
	case <-timer.C:
		p.logger.Infof("stopping entire process group %d with signal %s", p.cmd.Process.Pid, p.stopSig)
		if err := syscall.Kill(-p.cmd.Process.Pid, p.stopSig); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return false, errors.Wrapf(err, "error signaling process group %d with signal %s", p.cmd.Process.Pid, p.stopSig)
		}
	case <-p.managingCh:
		timer.Stop()
	}

	// Lastly, kill everything in the process group that remains after a longer wait
	var forceKilled bool
	// NOTE(benji): Wait for 2.5 minutes between SIGTERM of the process group and
	// SIGQUIT to ensure we are dealing with a real hang and not just slowness in
	// the pion code.
	timer2 := time.NewTimer(150 * time.Second)
	defer timer2.Stop()
	select {
	case <-timer2.C:
		p.logger.Infof("killing entire process group %d", p.cmd.Process.Pid)
		// NOTE(benji): Use a SIGQUIT here to get the stack trace of the running Golang module. Trying
		// to debug why `TestResourcelessModuleRemove` sometimes get to this step of `kill`. Golang
		// module must be "stuck" somewhere and presumably not yet; waiting on the `ctx.Done` channel
		// in its `main` method.
		if err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGQUIT); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return false, errors.Wrapf(err, "error killing process group %d", p.cmd.Process.Pid)
		}
		// NOTE(benji): Give the module a full 10 seconds to dump its goroutines. If we do not sleep
		// here, the testing object will cease executing and we will miss some goroutine output.
		time.Sleep(10 * time.Second)
		forceKilled = true
	case <-p.managingCh:
		timer2.Stop()
	}

	return forceKilled, nil
}

func isWaitErrUnknown(err string, forceKilled bool) bool {
	// This can easily happen if the process does not handle interrupts gracefully
	// and it won't provide us any exit code info.
	switch err {
	case "signal: interrupt", "signal: terminated", "signal: killed":
		return true
	}
	return false
}
