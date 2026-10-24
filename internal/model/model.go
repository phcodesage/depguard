// Package model defines the portable inventory and vulnerability report format.
package model

type Dependency struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Lockfile  string `json:"lockfile"`
	Location  string `json:"location"`
	Dev       bool   `json:"dev"`
}

type Runtime struct {
	Name     string `json:"name"`
	Declared string `json:"declared"`
	Source   string `json:"source"`
}

type Issue struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

type Finding struct {
	Dependency Dependency `json:"dependency"`
	ID         string     `json:"id"`
	URL        string     `json:"url"`
}

type Report struct {
	SchemaVersion   int          `json:"schema_version"`
	Root            string       `json:"root"`
	GeneratedAt     string       `json:"generated_at"`
	InventoryStatus string       `json:"inventory_status"`
	AdvisoryStatus  string       `json:"advisory_status"`
	Dependencies    []Dependency `json:"dependencies"`
	Runtimes        []Runtime    `json:"runtimes"`
	Findings        []Finding    `json:"findings"`
	Issues          []Issue      `json:"issues"`
	Limitations     []string     `json:"limitations"`
}
