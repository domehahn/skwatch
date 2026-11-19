package drift_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/domehahn/skwatch/pkg/drift"
)

func TestDrift(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "skwatch_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	fileA := filepath.Join(tmpDir, "SKILL.md")
	if err := os.WriteFile(fileA, []byte("# My Skill"), 0644); err != nil {
		t.Fatal(err)
	}

	digest1, err := drift.ComputeDirectoryDigest(tmpDir)
	if err != nil {
		t.Fatalf("failed to compute digest: %v", err)
	}

	report, err := drift.CheckDrift(tmpDir, digest1)
	if err != nil {
		t.Fatalf("check drift failed: %v", err)
	}
	if report.HasDrift {
		t.Errorf("expected no drift")
	}

	// Modify file
	if err := os.WriteFile(fileA, []byte("# My Tampered Skill"), 0644); err != nil {
		t.Fatal(err)
	}

	report2, err := drift.CheckDrift(tmpDir, digest1)
	if err != nil {
		t.Fatalf("check drift failed: %v", err)
	}
	if !report2.HasDrift {
		t.Errorf("expected drift after file modification")
	}
}
