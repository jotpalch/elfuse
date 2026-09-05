// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestParsePlatform(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"linux/arm64", "linux/arm64", true},
		{"linux/amd64", "linux/amd64", true},
		{"linux/arm64/v8", "linux/arm64", true},
		{"linux/aarch64", "linux/arm64", true},
		{"linux/x86_64", "linux/amd64", true},
		{"linux//", "", false},
		{"/arm64", "", false},
		{"linux/arm64/", "", false},
		{"linux/arm64/v8/extra", "", false},
		{"darwin/arm64", "", false},
		{"linux/riscv64", "", false},
		{"linux/arm/v7", "", false},
		{"linux/arm64/v9", "", false},
		{"linux/amd64/v3", "", false},
	} {
		p, err := parsePlatform(tc.in)
		if tc.ok != (err == nil) {
			t.Errorf("parsePlatform(%q) err = %v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && platformString(p) != tc.want {
			t.Errorf("parsePlatform(%q) = %q, want %q", tc.in, platformString(p), tc.want)
		}
	}
	if _, err := parsePlatform("darwin/arm64"); err == nil || !strings.Contains(err.Error(), "must be linux") {
		t.Errorf("non-linux error should explain the OS rule: %v", err)
	}
	if _, err := parsePlatform("linux/riscv64"); err == nil || !strings.Contains(err.Error(), "arm64 or amd64") {
		t.Errorf("unsupported-arch error should name the two guests: %v", err)
	}
}

func TestDefaultStoreFromEnv(t *testing.T) {
	t.Setenv("ELFUSE_OCI_STORE", "/x/y")
	got, err := defaultStore()
	if err != nil || got != "/x/y" {
		t.Fatalf("defaultStore = %q, %v", got, err)
	}
	t.Setenv("ELFUSE_OCI_STORE", "")
	got, err = defaultStore()
	if err != nil || !strings.HasSuffix(got, "/.local/share/elfuse/oci") {
		t.Fatalf("defaultStore fallback = %q, %v", got, err)
	}
}
