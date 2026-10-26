// Command renka is a small Matrix homeserver. The code is in internal/server.
package main

import "renka/internal/server"

// set at build time with -ldflags "-X main.version=..."
var version = "dev"

func main() { server.Main(version) }
