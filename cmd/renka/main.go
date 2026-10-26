// Command renka is a small Matrix homeserver. The code is in internal/server.
package main

import "renka/internal/server"

// version is set at build time: -ldflags "-X main.version=v0.1.0"
var version = "dev"

func main() { server.Main(version) }
