// Copyright 2026 elfuse contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const flockPoll = 50 * time.Millisecond

type flockFile struct {
	f *os.File
}

// Poll LOCK_NB so cancellation bounds the wait.
func acquireFlock(ctx context.Context, path string) (*flockFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			l := &flockFile{f: f}
			// Do not return a lock acquired after cancellation.
			if cerr := ctx.Err(); cerr != nil {
				l.Close()
				return nil, fmt.Errorf("lock %s: %w", path, cerr)
			}
			return l, nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, ctx.Err())
		case <-time.After(flockPoll):
		}
	}
}

func (l *flockFile) Close() error {
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	return l.f.Close()
}
