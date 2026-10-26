// Renka: a small single-server Matrix homeserver (client-server API, no federation).
package server

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	ServerName        string // the part after ":" in @user:server
	Listen            string
	PublicBaseURL     string // what clients use to reach us (for .well-known)
	Database          string
	MediaDir          string
	Registration      bool
	RegistrationToken string
	MaxUploadBytes    int64
	MemoryLimitMB     int64
	TrustProxy        bool   // use X-Forwarded-For for client IPs (only behind a reverse proxy)
	SearchAllUsers    bool   // user directory finds everyone, not just people you share a room with
	Push              bool   // send push notifications to push gateways
	Federation        bool   // talk to other Matrix servers
	FederationAddress string // host:port other servers connect to (.well-known/matrix/server)
	// FederationAllowPrivate lets federation reach private addresses (LAN tests only)
	FederationAllowPrivate bool
	MediaQuotaBytes        int64 // per-user upload storage cap (0 = unlimited; admins exempt)
	// TrustedKeyServers are asked for keys of servers that don't answer.
	TrustedKeyServers []string
	// RemoteMediaCacheBytes caps the copies of other servers' files (0 = no cap).
	RemoteMediaCacheBytes int64
}

func loadConfig(path string) (*Config, error) {
	c := &Config{
		Listen:                "127.0.0.1:8008",
		Database:              "data/renka.db",
		MediaDir:              "data/media",
		MaxUploadBytes:        50 << 20,
		MediaQuotaBytes:       1024 << 20,
		Push:                  true,
		TrustedKeyServers:     []string{"matrix.org"},
		RemoteMediaCacheBytes: 1024 << 20,
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, line)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"`)
		bad := func(what string) error { return fmt.Errorf("%s:%d: %s: %s, got %q", path, line, k, what, v) }
		// typos are errors, not silent 0/false
		b, boolErr := parseBool(v)
		num, numErr := strconv.ParseInt(v, 10, 64)
		switch k {
		case "server_name":
			c.ServerName = v
		case "listen":
			c.Listen = v
		case "public_base_url":
			c.PublicBaseURL = strings.TrimRight(v, "/")
		case "database":
			c.Database = v
		case "media_dir":
			c.MediaDir = v
		case "registration":
			if boolErr != nil {
				return nil, bad("expected true or false")
			}
			c.Registration = b
		case "registration_token":
			c.RegistrationToken = v
		case "max_upload_mb":
			if numErr != nil || num < 1 || num > 100_000 {
				return nil, bad("expected a whole number of MB between 1 and 100000")
			}
			c.MaxUploadBytes = num << 20
		case "memory_limit_mb":
			if numErr != nil || num < 0 || num > 1_000_000 {
				return nil, bad("expected a whole number of MB (0 = no limit)")
			}
			c.MemoryLimitMB = num
		case "trust_proxy":
			if boolErr != nil {
				return nil, bad("expected true or false")
			}
			c.TrustProxy = b
		case "federation":
			if boolErr != nil {
				return nil, bad("expected true or false")
			}
			c.Federation = b
		case "federation_address":
			if !validHostPort(v) {
				return nil, bad("expected host or host:port")
			}
			c.FederationAddress = v
		case "trusted_key_servers":
			c.TrustedKeyServers = nil
			for _, h := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
				if !validHostPort(h) {
					return nil, bad("expected a comma-separated list of server names")
				}
				c.TrustedKeyServers = append(c.TrustedKeyServers, h)
			}
		case "federation_allow_private":
			if boolErr != nil {
				return nil, bad("expected true or false")
			}
			c.FederationAllowPrivate = b
		case "push":
			if boolErr != nil {
				return nil, bad("expected true or false")
			}
			c.Push = b
		case "search_all_users":
			if boolErr != nil {
				return nil, bad("expected true or false")
			}
			c.SearchAllUsers = b
		case "remote_media_cache_mb":
			if numErr != nil || num < 0 || num > 100_000_000 {
				return nil, bad("expected a whole number of MB (0 = no limit)")
			}
			c.RemoteMediaCacheBytes = num << 20
		case "media_quota_mb":
			if numErr != nil || num < 0 || num > 100_000_000 {
				return nil, bad("expected a whole number of MB (0 = unlimited)")
			}
			c.MediaQuotaBytes = num << 20
		default:
			return nil, fmt.Errorf("%s:%d: unknown key %q", path, line, k)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if c.ServerName == "" {
		return nil, fmt.Errorf("server_name is required")
	}
	// It ends up in every user and room ID, so keep it a plain host[:port].
	if !validHostPort(c.ServerName) {
		return nil, fmt.Errorf("server_name %q must be a host name, optionally with :port", c.ServerName)
	}
	if c.PublicBaseURL == "" {
		c.PublicBaseURL = "https://" + c.ServerName
	}
	if !strings.HasPrefix(c.PublicBaseURL, "https://") && !strings.HasPrefix(c.PublicBaseURL, "http://") {
		return nil, fmt.Errorf("public_base_url %q must start with https:// (or http://)", c.PublicBaseURL)
	}
	if c.RegistrationToken != "" && len(c.RegistrationToken) < 8 {
		return nil, fmt.Errorf("registration_token is too short to resist guessing; use at least 8 characters")
	}
	return c, nil
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "true", "yes", "on", "1":
		return true, nil
	case "false", "no", "off", "0":
		return false, nil
	}
	return false, fmt.Errorf("not a boolean")
}

// validHostPort: host, host:port, [v6]:port or an IP.
func validHostPort(hp string) bool {
	host := hp
	if h, port, err := net.SplitHostPort(hp); err == nil {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return false
		}
		host = h
		if strings.Contains(h, ":") { // IPv6, already unbracketed
			return net.ParseIP(h) != nil
		}
	} else if strings.HasPrefix(hp, "[") && strings.HasSuffix(hp, "]") {
		return net.ParseIP(hp[1:len(hp)-1]) != nil
	} else if strings.Contains(hp, ":") {
		return false // bare IPv6 or a bad port: IDs would be ambiguous
	}
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func usage() {
	fmt.Fprintf(os.Stderr, `Renka - lightweight Matrix homeserver

  renka [-config renka.conf]                              run the server
  renka adduser [-config f] -u NAME [-p PASS] [-admin]   create a user
  renka passwd  [-config f] -u NAME [-p PASS]            reset a password
  renka admin   [-config f] COMMAND...                    run an admin command on the running server
                                                          (renka admin help lists them)
  renka version                                           show version
`)
}

var version = "dev"

// Main runs the renka command line. v is the build version.
func Main(v string) {
	version = v
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("renka", version)
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "adduser" || os.Args[1] == "passwd") {
		cmdUser(os.Args[1], os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		fs := flag.NewFlagSet("admin", flag.ExitOnError)
		cfgPath := fs.String("config", "renka.conf", "config file")
		fs.Parse(os.Args[2:])
		cfg, err := loadConfig(*cfgPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		os.Exit(cmdAdmin(cfg, fs.Args()))
	}
	fs := flag.NewFlagSet("renka", flag.ExitOnError)
	fs.Usage = usage
	cfgPath := fs.String("config", "renka.conf", "config file")
	fs.Parse(os.Args[1:])

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.MemoryLimitMB > 0 {
		debug.SetMemoryLimit(cfg.MemoryLimitMB << 20)
	}
	s, err := newServer(cfg)
	if err != nil {
		log.Fatalf("startup: %v", err)
	}
	s.startAdminBot()
	if err := s.ensureAdminRoom(); err != nil {
		log.Printf("admin room: %v", err)
	}
	if err := s.startAdminSocket(); err != nil {
		log.Printf("admin socket unavailable (renka admin won't work): %v", err)
	}
	defer s.stopAdminSocket()
	// cancelled on shutdown so long-polls return right away
	base, cancelBase := context.WithCancel(context.Background())
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		// no WriteTimeout: /sync and big downloads take a while
		ReadTimeout: 10 * time.Minute,
		IdleTimeout: 120 * time.Second,
		BaseContext: func(net.Listener) context.Context { return base },
	}
	srv.RegisterOnShutdown(cancelBase) // runs after the listener is closed
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		log.Printf("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	log.Printf("renka %s for %s listening on %s", version, cfg.ServerName, cfg.Listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	// wait for in-flight requests before closing the db
	<-stopped
	s.db.Close()
	log.Printf("stopped")
}

func cmdUser(cmd string, args []string) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "renka.conf", "config file")
	name := fs.String("u", "", "username (localpart)")
	pass := fs.String("p", "", "password (prompted if empty)")
	admin := fs.Bool("admin", false, "make the user an admin")
	fs.Parse(args)
	if *name == "" {
		usage()
		os.Exit(2)
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if !validLocalpart(strings.ToLower(*name)) {
		log.Fatal("username may only contain a-z, 0-9 and ._=-/+")
	}
	if *pass == "" {
		*pass = readSecret("Password (8+ characters, not shown): ")
		if len(*pass) >= 8 && readSecret("Same password again: ") != *pass {
			log.Fatal("the passwords don't match")
		}
	}
	if len(*pass) < 8 {
		log.Fatal("password must be at least 8 characters")
	}
	s, err := newServer(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer s.db.Close()
	uid := "@" + strings.ToLower(*name) + ":" + cfg.ServerName
	if cmd == "adduser" {
		if err := s.createUser(strings.ToLower(*name), *pass, *admin); err != nil {
			log.Fatal(err)
		}
		fmt.Println("created", uid)
		return
	}
	// log out everywhere. Separate process, so no stream positions here;
	// deleting the devices kills the tokens.
	tx, err := s.db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Rollback()
	res, err := tx.Exec("UPDATE users SET password_hash=? WHERE user_id=?", hashPassword(*pass), uid)
	if err != nil {
		log.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		log.Fatal("no such user")
	}
	var revoked int64
	for _, t := range []string{"devices", "device_keys", "one_time_keys", "fallback_keys", "to_device", "pushers"} {
		res, err := tx.Exec("DELETE FROM "+t+" WHERE user_id = ?", uid)
		if err != nil {
			log.Fatal(err)
		}
		if t == "devices" {
			revoked, _ = res.RowsAffected()
		}
	}
	if err := tx.Commit(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("password changed for %s; %d session(s) logged out\n", uid, revoked)
}
