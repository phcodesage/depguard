// Package inventory reads project metadata without installing or executing it.
package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/phcodesage/depguard/internal/model"
)

const maxFileSize = 32 << 20

var npmVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
var composerVersion = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}(?:[-+][0-9A-Za-z.-]+)?$`)

// Collect scans a directory tree. Paths in the report are relative to its root.
func Collect(root string) (model.Report, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return model.Report{}, err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return model.Report{}, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return model.Report{}, err
	}
	if !info.IsDir() {
		return model.Report{}, fmt.Errorf("target must be a directory")
	}
	r := model.Report{
		SchemaVersion: 1, Root: absolute, InventoryStatus: "complete", AdvisoryStatus: "not_requested",
		Dependencies: []model.Dependency{}, Runtimes: []model.Runtime{}, Findings: []model.Finding{}, Issues: []model.Issue{},
		Limitations: []string{
			"Runtime declarations are inventory only; deployed PHP/Node versions and runtime advisories are not checked.",
			"Known advisory matches do not establish absence of malware or undisclosed vulnerabilities.",
			"Lockfiles describe intended dependencies; installed artifacts and integrity are not verified.",
			"No updates, compatibility resolution, reachability analysis, or application tests are performed.",
		},
	}
	metadata := 0
	lockfiles := 0
	err = filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
		rel, _ := filepath.Rel(absolute, path)
		rel = filepath.ToSlash(rel)
		if walkErr != nil {
			addIssue(&r, rel, "cannot access path")
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".hg", ".svn", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		switch name {
		case "package-lock.json", "composer.lock", "package.json", "composer.json", ".nvmrc", ".node-version", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lock", "bun.lockb":
		default:
			return nil
		}
		metadata++
		if entry.Type()&os.ModeSymlink != 0 {
			addIssue(&r, rel, "symlinked metadata is not followed")
			return nil
		}
		if !entry.Type().IsRegular() {
			addIssue(&r, rel, "metadata must be a regular file")
			return nil
		}
		switch name {
		case "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lock", "bun.lockb":
			addIssue(&r, rel, "unsupported lockfile; dependencies in this file were not scanned")
			return nil
		}
		data, err := readFile(path)
		if err != nil {
			addIssue(&r, rel, err.Error())
			return nil
		}
		switch name {
		case "package-lock.json":
			lockfiles++
			err = readNPM(data, rel, &r)
		case "composer.lock":
			lockfiles++
			err = readComposer(data, rel, &r)
		case "package.json", "composer.json":
			err = readManifest(data, name, rel, &r)
			lock := "package-lock.json"
			if name == "composer.json" {
				lock = "composer.lock"
			}
			if _, statErr := os.Lstat(filepath.Join(filepath.Dir(path), lock)); statErr != nil {
				addIssue(&r, rel, "no readable "+lock+" alongside manifest; exact dependency coverage is unknown")
			}
		case ".nvmrc", ".node-version":
			value := strings.TrimSpace(string(data))
			if value == "" {
				err = fmt.Errorf("empty runtime declaration")
			} else {
				r.Runtimes = append(r.Runtimes, model.Runtime{Name: "node", Declared: value, Source: rel})
			}
		}
		if err != nil {
			addIssue(&r, rel, err.Error())
		}
		return nil
	})
	if err != nil {
		return model.Report{}, err
	}
	if metadata == 0 {
		addIssue(&r, ".", "no supported project metadata found")
	} else if lockfiles == 0 {
		addIssue(&r, ".", "no supported lockfiles found; exact dependency coverage is unknown")
	}
	sort.Slice(r.Dependencies, func(i, j int) bool {
		a, b := r.Dependencies[i], r.Dependencies[j]
		return a.Lockfile+"\x00"+a.Location < b.Lockfile+"\x00"+b.Location
	})
	sort.Slice(r.Issues, func(i, j int) bool {
		return r.Issues[i].Path+"\x00"+r.Issues[i].Message < r.Issues[j].Path+"\x00"+r.Issues[j].Message
	})
	return r, nil
}

func addIssue(r *model.Report, path, message string) {
	r.InventoryStatus = "partial"
	r.Issues = append(r.Issues, model.Issue{Path: path, Message: message})
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open metadata")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("metadata must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read metadata")
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("metadata exceeds 32 MiB limit")
	}
	return data, nil
}

func readNPM(data []byte, path string, r *model.Report) error {
	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
			Link     bool   `json:"link"`
			Dev      bool   `json:"dev"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("invalid npm lockfile JSON")
	}
	if lock.LockfileVersion != 2 && lock.LockfileVersion != 3 {
		return fmt.Errorf("only npm lockfile versions 2 and 3 are supported")
	}
	if lock.Packages == nil {
		return fmt.Errorf("npm lockfile is missing its packages object")
	}
	for location, pkg := range lock.Packages {
		if location == "" || pkg.Link {
			continue
		}
		// Workspaces appear outside node_modules and are project code, not registry dependencies.
		index := strings.LastIndex(location, "node_modules/")
		if index < 0 {
			continue
		}
		name := pkg.Name
		if name == "" {
			name = location[index+len("node_modules/"):]
		}
		if name == "" || !npmVersion.MatchString(pkg.Version) {
			addIssue(r, path, "cannot query non-release npm dependency at "+location)
			continue
		}
		if strings.HasPrefix(pkg.Resolved, "git") || strings.HasPrefix(pkg.Resolved, "file:") {
			addIssue(r, path, "git/local npm dependency is outside registry advisory coverage at "+location)
			continue
		}
		r.Dependencies = append(r.Dependencies, model.Dependency{Ecosystem: "npm", Name: name, Version: pkg.Version, Lockfile: path, Location: location, Dev: pkg.Dev})
	}
	return nil
}

func readComposer(data []byte, path string, r *model.Report) error {
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var lock struct {
		Packages []pkg `json:"packages"`
		Dev      []pkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("invalid Composer lockfile JSON")
	}
	if lock.Packages == nil {
		return fmt.Errorf("Composer lockfile is missing its packages array")
	}
	for _, group := range []struct {
		packages []pkg
		dev      bool
	}{{lock.Packages, false}, {lock.Dev, true}} {
		for _, p := range group.packages {
			version := strings.TrimPrefix(p.Version, "v")
			if p.Name == "" || !composerVersion.MatchString(version) || strings.Contains(strings.ToLower(version), "dev") {
				addIssue(r, path, "cannot query non-release or unnamed Composer dependency")
				continue
			}
			r.Dependencies = append(r.Dependencies, model.Dependency{Ecosystem: "Packagist", Name: p.Name, Version: version, Lockfile: path, Location: p.Name, Dev: group.dev})
		}
	}
	return nil
}

func readManifest(data []byte, name, path string, r *model.Report) error {
	var manifest *struct {
		Engines map[string]string          `json:"engines"`
		Require map[string]json.RawMessage `json:"require"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || manifest == nil {
		return fmt.Errorf("invalid manifest JSON")
	}
	if name == "package.json" && manifest.Engines["node"] != "" {
		r.Runtimes = append(r.Runtimes, model.Runtime{Name: "node", Declared: manifest.Engines["node"], Source: path})
	}
	if name == "composer.json" && manifest.Require["php"] != nil {
		var value string
		if err := json.Unmarshal(manifest.Require["php"], &value); err != nil {
			return fmt.Errorf("invalid PHP runtime constraint")
		}
		r.Runtimes = append(r.Runtimes, model.Runtime{Name: "php", Declared: value, Source: path})
	}
	return nil
}
