package main

import (
	"strings"
	"testing"
)

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

func TestRenderCaddyfileDebugOff(t *testing.T) {
	got := renderCaddyfile("example.com", "53", "example.net", "1.1.1.1:53", false)
	if strings.Contains(got, "debug") {
		t.Errorf("debug directive present without -debug:\n%s", got)
	}
	// The rest of the config must still compile-shaped: one server block
	// with the plugins we always emit.
	for _, want := range []string{
		"example.com:53 {",
		"tailscale example.net {",
		"forward . 1.1.1.1:53",
		"\n\tlog\n",
		"\n\terrors\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderCaddyfileDebugOn(t *testing.T) {
	got := renderCaddyfile("example.com", "53", "example.net", "/etc/resolv.conf", true)
	if !strings.Contains(got, "\n\tdebug\n") {
		t.Errorf("debug directive not on its own line in:\n%s", got)
	}
	// debug must not glue onto the forward line or swallow following lines.
	if !strings.Contains(got, "forward . /etc/resolv.conf\n\tdebug\n\tlog\n") {
		t.Errorf("unexpected directive layout in:\n%s", got)
	}
}

func TestEnvBoolOr(t *testing.T) {
	t.Setenv("DEBUG_TEST_ON", "true")
	t.Setenv("DEBUG_TEST_OFF", "0")
	t.Setenv("DEBUG_TEST_JUNK", "maybe")
	t.Setenv("DEBUG_TEST_EMPTY", "  ")
	if !envBoolOr("DEBUG_TEST_ON", false) {
		t.Error("DEBUG_TEST_ON=true should parse true")
	}
	if envBoolOr("DEBUG_TEST_OFF", true) {
		t.Error("DEBUG_TEST_OFF=0 should parse false")
	}
	// Unset, empty or unparseable fall back to the default, so a broken
	// DEBUG value can never enable debugging by accident.
	if envBoolOr("DEBUG_TEST_JUNK", false) {
		t.Error("unparseable value must fall back to the default")
	}
	if envBoolOr("DEBUG_TEST_EMPTY", false) {
		t.Error("blank value must fall back to the default")
	}
	if envBoolOr("DEBUG_TEST_UNSET", false) {
		t.Error("unset value must fall back to the default")
	}
}
