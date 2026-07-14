package customrules

import (
	"context"
	"errors"
	"testing"
)

func TestDownloadSkipsExistingDirectory(t *testing.T) {
	if err := DefaultProvider.Download(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("expected existing directory to be skipped, got %v", err)
	}
}

func TestEnsureDirectoryHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := EnsureDirectory(ctx, t.TempDir()+"/finger-rules")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}
