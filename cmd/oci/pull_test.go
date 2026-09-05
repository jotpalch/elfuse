// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func platformImage(t *testing.T, platform v1.Platform) v1.Image {
	t.Helper()
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: platform.Architecture,
		OS:           platform.OS,
		Variant:      platform.Variant,
		RootFS:       v1.RootFS{Type: "layers"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return mutate.MediaType(img, types.OCIManifestSchema1)
}

func imageDigest(t *testing.T, img v1.Image) v1.Hash {
	t.Helper()
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestNormalizeRef(t *testing.T) {
	sha := "sha256:" + strings.Repeat("0", 64)
	for _, tc := range []struct{ in, want string }{
		{"alpine", "index.docker.io/library/alpine:latest"},
		{"alpine:3", "index.docker.io/library/alpine:3"},
		{"foo/bar", "index.docker.io/foo/bar:latest"},
		{"docker.io/alpine", "index.docker.io/library/alpine:latest"},
		{"ghcr.io/foo/bar:v1", "ghcr.io/foo/bar:v1"},
		{"ghcr.io/foo/bar", "ghcr.io/foo/bar:latest"},
		{"localhost/foo", "localhost/foo:latest"},
		{"localhost:5000/foo", "localhost:5000/foo:latest"},
		{"alpine@" + sha, "index.docker.io/library/alpine@" + sha},
		{"registry.example.com:8443/a/b:t", "registry.example.com:8443/a/b:t"},
	} {
		got, err := normalizeRef(tc.in)
		if err != nil || got.Name() != tc.want {
			t.Errorf("normalizeRef(%q) = %v, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "Alpine", "alpine:", "a@sha256:short"} {
		if _, err := normalizeRef(bad); err == nil {
			t.Errorf("normalizeRef(%q) must fail", bad)
		}
	}
}

func TestPullFlagParsing(t *testing.T) {
	var target cli
	parser, err := newParser(os.Stdout, os.Stderr, &target)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := parser.Parse([]string{"pull", "--timeout", "5s", "x:1", "--platform", "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Command() != "pull <ref>" || target.Pull.Ref != "x:1" || target.Pull.Timeout.String() != "5s" || target.Pull.Platform != "linux/amd64" {
		t.Fatalf("parsed command %q: %+v", ctx.Command(), target.Pull)
	}
	if _, err := parser.Parse([]string{"pull", "a", "b"}); err == nil {
		t.Fatal("two positionals must fail")
	}
}

func TestSelectIndexImage(t *testing.T) {
	arm := v1.Platform{OS: "linux", Architecture: "arm64"}
	amd := v1.Platform{OS: "linux", Architecture: "amd64"}
	armImage := platformImage(t, arm)
	amdImage := platformImage(t, amd)
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amdImage},
		mutate.IndexAddendum{Add: armImage},
	)
	got, err := selectIndexImage(index, arm)
	if err != nil {
		t.Fatal(err)
	}
	if imageDigest(t, got) != imageDigest(t, armImage) {
		t.Fatal("the later matching platformless image was not selected")
	}

	declared := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amdImage, Descriptor: v1.Descriptor{Platform: &amd}},
	)
	if _, err := selectIndexImage(declared, arm); err == nil || !strings.Contains(err.Error(), "no image") {
		t.Fatalf("no-match error = %v", err)
	}
}

func TestSelectIndexImagePlatformRules(t *testing.T) {
	arm := v1.Platform{OS: "linux", Architecture: "arm64"}
	armV8 := v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	amd := v1.Platform{OS: "linux", Architecture: "amd64"}

	v8Image := platformImage(t, armV8)
	v8Index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: v8Image, Descriptor: v1.Descriptor{Platform: &armV8}},
	)
	if _, err := selectIndexImage(v8Index, arm); err != nil {
		t.Fatalf("arm64/v8 selection: %v", err)
	}

	amdV3 := v1.Platform{OS: "linux", Architecture: "amd64", Variant: "v3"}
	v3Index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: platformImage(t, amdV3), Descriptor: v1.Descriptor{Platform: &amdV3}},
	)
	if _, err := selectIndexImage(v3Index, amd); err == nil || !strings.Contains(err.Error(), "no image") {
		t.Fatalf("amd64/v3 selection error = %v", err)
	}

	mismatch := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: platformImage(t, amd), Descriptor: v1.Descriptor{Platform: &arm}},
	)
	if _, err := selectIndexImage(mismatch, arm); err == nil || !strings.Contains(err.Error(), "image platform") {
		t.Fatalf("config mismatch error = %v", err)
	}

	nested := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: empty.Index, Descriptor: v1.Descriptor{Platform: &arm}},
	)
	if _, err := selectIndexImage(nested, arm); err == nil || !strings.Contains(err.Error(), "index child") {
		t.Fatalf("nested-index error = %v", err)
	}
}

func TestDefaultKeychainUsesCredentialHelper(t *testing.T) {
	helper := writeShellStub(t, "docker-credential-elfuse-test", `
test "$1" = get || exit 1
read server
test "$server" = registry.example.com || exit 1
printf '%s\n' '{"Username":"review-user","Secret":"review-secret"}'
`)
	prependPath(t, filepath.Dir(helper))
	configDir := t.TempDir()
	config := []byte(`{"credHelpers":{"registry.example.com":"elfuse-test"}}`)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), config, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", configDir)
	ref, err := name.ParseReference("registry.example.com/private/image:1")
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := authn.DefaultKeychain.Resolve(ref.Context())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authenticator.Authorization()
	if err != nil {
		t.Fatal(err)
	}
	if auth.Username != "review-user" || auth.Password != "review-secret" {
		t.Fatalf("helper credentials = %q/%q", auth.Username, auth.Password)
	}
}

func TestConcurrentPullsDoNotSerializeFetch(t *testing.T) {
	s := tempStore(t)
	image := platformImage(t, v1.Platform{OS: "linux", Architecture: "arm64"})
	entered := make(chan struct{})
	release := make(chan struct{})
	fetch := func(ctx context.Context, ref name.Reference, _ v1.Platform) (v1.Image, error) {
		if strings.Contains(ref.Name(), "slow:1") {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return image, nil
	}
	slowErr := make(chan error, 1)
	go func() {
		slowErr <- pullImageWithFetcher(context.Background(), s, "slow:1", defaultPlatform, fetch)
	}()
	<-entered
	fastErr := make(chan error, 1)
	go func() {
		fastErr <- pullImageWithFetcher(context.Background(), s, "fast:1", defaultPlatform, fetch)
	}()
	select {
	case err := <-fastErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fast pull blocked on the slow pull's registry transfer")
	}
	close(release)
	if err := <-slowErr; err != nil {
		t.Fatal(err)
	}
	index, err := s.rootIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 2 {
		t.Fatalf("root descriptors = %d, want 2", len(index.Manifests))
	}
}

func TestPullRegistryRoundTrip(t *testing.T) {
	if os.Getenv("ELFUSE_OCI_NETTEST") == "" {
		t.Skip("set ELFUSE_OCI_NETTEST=1 to pull from a real registry")
	}
	s := tempStore(t)
	var err error
	captureOutput(t, func() {
		err = run([]string{"pull", "--store", s.root, "alpine:3"})
	})
	if err != nil {
		t.Fatal(err)
	}
	index, err := s.rootIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Manifests) != 1 {
		t.Fatalf("root descriptors = %d, want 1", len(index.Manifests))
	}
	nestedBytes, err := s.blobBytes(index.Manifests[0].Digest)
	if err != nil {
		t.Fatal(err)
	}
	var nested v1.IndexManifest
	if err := json.Unmarshal(nestedBytes, &nested); err != nil {
		t.Fatal(err)
	}
	if len(nested.Manifests) != 1 || nested.Manifests[0].Digest.String() == "" {
		t.Fatalf("nested index = %+v", nested)
	}
	manifest := nested.Manifests[0].Digest
	if _, err := os.Stat(filepath.Join(s.root, "blobs", manifest.Algorithm, manifest.Hex)); err != nil {
		t.Errorf("manifest blob %s: %v", manifest, err)
	}
}

func TestPullCommandRefusesNegativeTimeout(t *testing.T) {
	cmd := pullCommand{
		commonFlags: commonFlags{Store: t.TempDir(), Platform: platformString(defaultPlatform)},
		Timeout:     -1,
		Ref:         "x:1",
	}
	if err := cmd.Run(); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("error = %v", err)
	}
}
