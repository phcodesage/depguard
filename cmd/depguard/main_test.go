package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phcodesage/depguard/internal/model"
)

func TestInventoryJSONAndExitCodes(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "composer.lock"), []byte(`{"packages":[]}`), 0644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"inventory", "--format", "json", root}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, &errOut)
	}
	var report model.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.AdvisoryStatus != "not_requested" || report.InventoryStatus != "complete" || report.GeneratedAt == "" {
		t.Fatalf("unexpected report: %+v", report)
	}
	out.Reset()
	if code := run(context.Background(), []string{"inventory", t.TempDir()}, &out, &errOut); code != 2 {
		t.Fatalf("incomplete inventory returned %d", code)
	}
}

func TestInvalidArguments(t *testing.T) {
	for _, args := range [][]string{{"apply"}, {"scan"}, {"inventory", "--format", "xml", "."}, {"inventory", "--timeout", "0s", "."}, {"inventory", ".", "--format", "json"}} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut); code != 2 {
			t.Errorf("%v returned %d", args, code)
		}
	}
}

func TestTerminalOutputEscapesUntrustedMetadata(t *testing.T) {
	var out bytes.Buffer
	err := renderText(&out, model.Report{Dependencies: []model.Dependency{{Name: "evil\x1b[2J", Version: "1.0.0"}}, Findings: []model.Finding{}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Fatal("unescaped terminal control character")
	}
}
