//go:build !linux

package server

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

var stdin = bufio.NewReader(os.Stdin)

func readSecret(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := stdin.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// Renka targets Linux; elsewhere rely on the socket file's 0600 mode.
func umask(int) int { return 0 }

func peerAllowed(net.Conn) bool { return true }
