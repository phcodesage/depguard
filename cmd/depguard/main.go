// DepGuard inventories PHP/Node projects and checks lockfiles against OSV.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/phcodesage/depguard/internal/advisory"
	"github.com/phcodesage/depguard/internal/inventory"
	"github.com/phcodesage/depguard/internal/model"
)

const version = "0.1.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, "Usage: depguard <inventory|scan> [--format text|json] [--timeout 2m] <directory>\n       depguard version\n\nScan sends package names and versions to OSV.dev. Inventory makes no network requests.\nPlace flags before the directory. Exit codes: 0 complete/no findings, 1 findings, 2 incomplete/error.")
		return 0
	}
	if args[0] == "version" {
		fmt.Fprintln(out, version)
		return 0
	}
	if args[0] != "scan" && args[0] != "inventory" {
		fmt.Fprintln(errOut, "unknown command; use depguard help")
		return 2
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(errOut)
	format := flags.String("format", "text", "output format: text or json")
	timeout := flags.Duration("timeout", 2*time.Minute, "total advisory lookup timeout")
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 1 || (*format != "text" && *format != "json") || *timeout <= 0 {
		fmt.Fprintln(errOut, "provide one directory, a valid format, and a positive timeout; use depguard help")
		return 2
	}
	r, err := inventory.Collect(flags.Arg(0))
	if err != nil {
		fmt.Fprintln(errOut, "cannot inventory target:", err)
		return 2
	}
	if args[0] == "scan" {
		lookupCtx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		r.Findings, err = advisory.NewClient().Scan(lookupCtx, r.Dependencies)
		r.AdvisoryStatus = "complete"
		if err != nil {
			r.AdvisoryStatus = "partial"
			r.Issues = append(r.Issues, model.Issue{Path: "OSV", Message: err.Error()})
		}
	}
	r.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	if *format == "json" {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(r)
	} else {
		err = renderText(out, r)
	}
	if err != nil {
		fmt.Fprintln(errOut, "cannot write report:", err)
		return 2
	}
	if r.InventoryStatus != "complete" || r.AdvisoryStatus == "partial" {
		return 2
	}
	if len(r.Findings) > 0 {
		return 1
	}
	return 0
}

func renderText(out io.Writer, r model.Report) error {
	// Quote metadata from untrusted projects to prevent terminal control sequences.
	if _, err := fmt.Fprintf(out, "DepGuard %s\nTarget: %q\nInventory: %s | Dependency advisory lookup: %s\nDependencies: %d | Known advisory matches: %d\n", version, r.Root, r.InventoryStatus, r.AdvisoryStatus, len(r.Dependencies), len(r.Findings)); err != nil {
		return err
	}
	for _, dep := range r.Dependencies {
		if _, err := fmt.Fprintf(out, "  %s %q@%q dev=%t (%q: %q)\n", dep.Ecosystem, dep.Name, dep.Version, dep.Dev, dep.Lockfile, dep.Location); err != nil {
			return err
		}
	}
	for _, runtime := range r.Runtimes {
		if _, err := fmt.Fprintf(out, "Runtime declaration (unverified): %s %q in %q\n", runtime.Name, runtime.Declared, runtime.Source); err != nil {
			return err
		}
	}
	for _, finding := range r.Findings {
		if _, err := fmt.Fprintf(out, "MATCH %q@%q: %q\n  %s\n", finding.Dependency.Name, finding.Dependency.Version, finding.ID, finding.URL); err != nil {
			return err
		}
	}
	for _, issue := range r.Issues {
		if _, err := fmt.Fprintf(out, "INCOMPLETE %q: %q\n", issue.Path, issue.Message); err != nil {
			return err
		}
	}
	for _, limitation := range r.Limitations {
		if _, err := fmt.Fprintln(out, "Scope:", limitation); err != nil {
			return err
		}
	}
	return nil
}
