//go:build linux

package server

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// stdin is shared so two prompts in a row work with piped input too.
var stdin = bufio.NewReader(os.Stdin)

// readSecret reads a line from the terminal without echoing it.
func readSecret(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if t, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
		quiet := *t
		quiet.Lflag &^= unix.ECHO
		if unix.IoctlSetTermios(fd, unix.TCSETS, &quiet) == nil {
			defer func() {
				unix.IoctlSetTermios(fd, unix.TCSETS, t)
				fmt.Fprintln(os.Stderr)
			}()
		}
	}
	line, _ := stdin.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func umask(m int) int { return syscall.Umask(m) }

// peerAllowed: root or our own uid.
func peerAllowed(conn net.Conn) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return false
	}
	return cred.Uid == 0 || int(cred.Uid) == os.Getuid()
}
