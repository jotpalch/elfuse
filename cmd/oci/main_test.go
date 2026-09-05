// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"testing"
)

// TestMain isolates the tests from the user's store; os.Exit skips defers.
func TestMain(m *testing.M) {
	sandbox, err := os.MkdirTemp("", "elfuse-oci-test-store-")
	if err != nil {
		panic(err)
	}
	os.Setenv("ELFUSE_OCI_STORE", sandbox)
	code := m.Run()
	if err := os.RemoveAll(sandbox); err != nil {
		fmt.Fprintf(os.Stderr, "elfuse-oci test: sandbox store left behind: %v\n", err)
	}
	os.Exit(code)
}
