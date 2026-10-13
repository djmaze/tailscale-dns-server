package main

import "testing"

func TestParseUpstreamDNSTargets(t *testing.T) {
	for _, s := range []string{
		"/etc/resolv.conf",            // default: system resolver config
		"1.1.1.1:53 8.8.8.8:53",       // explicit resolvers
		"1.1.1.1",                     // bare host, forward assumes :53
		"[fd00::1]:53",                // bracketed IPv6
		"resolver.lan",                // hostname
		"/etc/resolv.conf 1.1.1.1:53", // file and address together
	} {
		got, err := parseUpstreamDNS(s)
		if err != nil {
			t.Errorf("parseUpstreamDNS(%q): unexpected error %v", s, err)
			continue
		}
		if got != s {
			t.Errorf("parseUpstreamDNS(%q) = %q, want it unchanged", s, got)
		}
	}
}

func TestParseUpstreamDNSNormalize(t *testing.T) {
	got, err := parseUpstreamDNS("  1.1.1.1:53\t8.8.8.8:53  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "1.1.1.1:53 8.8.8.8:53"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseUpstreamDNSRejects(t *testing.T) {
	for _, s := range []string{
		"",                     // nothing to forward to
		"   ",                  // only whitespace
		"1.1.1.1:0",            // port 0
		"1.1.1.1:65536",        // port out of range
		"1.1.1.1:notaport",     // non-numeric port
		"1.1.1.1:53; rm -rf /", // Caddyfile injection attempt
		"1.1.1.1:53}\n\tlog",   // brace/newline injection attempt
		"/",                    // bare slash, not a config path
		"etc/resolv.conf",      // relative path
		"[fd00::1]53",          // bracketed host must be [v6]:port
		"1.1.1.1:53:53",        // double port
	} {
		if got, err := parseUpstreamDNS(s); err == nil {
			t.Errorf("parseUpstreamDNS(%q) = %q, want an error", s, got)
		}
	}
}
