package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func write(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestMixedProjectAndIgnoredDirectories(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", `{"engines":{"node":">=22"}}`)
	write(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{
		"":{"name":"application","version":"1.0.0"},
		"node_modules/alias":{"name":"actual-package","version":"2.0.0"},
		"node_modules/a/node_modules/@scope/nested":{"version":"1.2.3","dev":true},
		"node_modules/workspace":{"resolved":"packages/workspace","link":true},
		"packages/workspace":{"name":"workspace","version":"1.0.0"}
	}}`)
	write(t, root, "composer.json", `{"require":{"php":"^8.3","vendor/library":"^1"}}`)
	write(t, root, "composer.lock", `{"packages":[{"name":"vendor/library","version":"v1.2.0"}],"packages-dev":[{"name":"vendor/test","version":"2.0.0"}]}`)
	write(t, root, "node_modules/ignored/package-lock.json", `invalid`)
	write(t, root, "vendor/ignored/composer.lock", `invalid`)
	write(t, root, ".git/package-lock.json", `invalid`)
	write(t, root, ".nvmrc", "22\n")
	r, err := Collect(root)
	if err != nil {
		t.Fatal(err)
	}
	if r.InventoryStatus != "complete" || len(r.Dependencies) != 4 || len(r.Runtimes) != 3 {
		t.Fatalf("unexpected report: %+v", r)
	}
	got := map[string]bool{}
	for _, dep := range r.Dependencies {
		got[dep.Name+"@"+dep.Version] = dep.Dev
	}
	if _, exists := got["actual-package@2.0.0"]; !exists {
		t.Fatal("npm alias did not use real package identity")
	}
	if !got["@scope/nested@1.2.3"] || !got["vendor/test@2.0.0"] {
		t.Fatal("development dependencies missing")
	}
	if _, exists := got["vendor/library@1.2.0"]; !exists {
		t.Fatal("Composer version not normalized")
	}
}

func TestIncompleteInventories(t *testing.T) {
	cases := []struct{ name, file, contents string }{
		{"empty", "", ""},
		{"missing lockfile", "package.json", `{}`},
		{"only runtime declaration", ".nvmrc", "22"},
		{"null manifest", "package.json", " null\n"},
		{"legacy npm", "package-lock.json", `{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0"}}}`},
		{"unsupported lockfile", "pnpm-lock.yaml", "lockfileVersion: '9.0'"},
		{"malformed", "composer.lock", `{"packages":`},
		{"missing Composer packages", "composer.lock", `{}`},
		{"missing npm packages", "package-lock.json", `{"lockfileVersion":3}`},
		{"unversioned dependency", "package-lock.json", `{"lockfileVersion":2,"packages":{"node_modules/a":{"version":"git+https://example.invalid/repo"}}}`},
		{"git dependency", "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","resolved":"git+https://example.invalid/repo"}}}`},
		{"Composer branch", "composer.lock", `{"packages":[{"name":"vendor/a","version":"dev-main"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.file != "" {
				write(t, root, tc.file, tc.contents)
			}
			r, err := Collect(root)
			if err != nil {
				t.Fatal(err)
			}
			if r.InventoryStatus != "partial" || len(r.Issues) == 0 {
				t.Fatalf("incomplete scan was not flagged: %+v", r)
			}
		})
	}
}

func TestNestedProjectsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	write(t, root, "apps/api/composer.lock", `{"packages":[]}`)
	if runtime.GOOS != "windows" {
		outside := t.TempDir()
		write(t, outside, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/secret":{"version":"1.0.0"}}}`)
		if err := os.Symlink(filepath.Join(outside, "package-lock.json"), filepath.Join(root, "package-lock.json")); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Collect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Dependencies) != 0 {
		t.Fatal("followed a metadata symlink")
	}
	if runtime.GOOS != "windows" {
		found := false
		for _, issue := range r.Issues {
			if strings.Contains(issue.Message, "symlink") {
				found = true
			}
		}
		if !found {
			t.Fatalf("symlink not flagged: %+v", r.Issues)
		}
	}
}

func TestInvalidTarget(t *testing.T) {
	if _, err := Collect(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("accepted missing target")
	}
}
