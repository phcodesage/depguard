# DepGuard

[![CI](https://github.com/phcodesage/depguard/actions/workflows/ci.yml/badge.svg)](https://github.com/phcodesage/depguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Inspect PHP and Node.js projects for known dependency vulnerabilities. Build
toward safer, reviewable upgrades with evidence for every decision.

**Early development:** this repository contains a working read-only scanner.
Automatic upgrades, runtime vulnerability checks, and compatibility planning are
on the [roadmap](docs/ROADMAP.md). DepGuard does not claim that a clean report proves
a dependency is safe.

## Quick start

Requires Go 1.25 or newer. No npm, PHP, or Composer installation is required to
run the scanner. Run these commands from your own clone of this repository:

```sh
git clone https://github.com/phcodesage/depguard.git
cd depguard
go build -o bin/depguard ./cmd/depguard

# Local inventory; makes no network requests.
./bin/depguard inventory /path/to/your/project

# Check exact locked package versions against OSV.dev.
./bin/depguard scan /path/to/your/project

# Machine-readable output. Put flags before the target directory.
./bin/depguard scan --format json /path/to/your/project > report.json
```

On Windows, build with `go build -o bin/depguard.exe ./cmd/depguard` and run
`.\bin\depguard.exe`. You can also use `go run ./cmd/depguard inventory PATH`
on any supported platform.

Try the [metadata-only example](examples/README.md) without installing dependencies:

```sh
go run ./cmd/depguard inventory examples/mixed-project
go run ./cmd/depguard scan examples/mixed-project
```

The example deliberately names a vulnerable package; its online scan should
produce findings and exit 1. These are demonstration files, not an application.

## What works today

- Recursively discover `package-lock.json` versions 2/3 and `composer.lock`.
- Include direct, transitive, and development dependencies from supported locks.
- Handle scoped npm names, nested installations, aliases with explicit names,
  and workspace links without treating project workspace code as registry packages.
- Query [OSV](https://osv.dev/) by exact ecosystem, package name, and version.
  Deduplicate requests, batch lookups, follow pagination, and link advisory IDs.
- List runtime declarations from `package.json` (`engines.node`),
  `composer.json` (`require.php`), `.nvmrc`, and `.node-version`.
- Produce text or JSON reports with explicit inventory and advisory lookup status.
- Flag missing, malformed, oversized, symlinked, and unsupported metadata;
  preserve findings if a later advisory request fails.

The scanner skips `.git`, `.hg`, `.svn`, `node_modules`, and `vendor` directories.
It does not follow symlinks discovered inside the target. An explicitly supplied
root symlink is resolved. Individual metadata files are limited to 32 MiB.

## Scope and limitations

The current scanner checks **known dependency advisories**. Runtime declarations
are reported as unverified inventory: they do not establish which PHP or Node.js
binary runs in production. Docker images, system packages, PHP extensions, runtime
CVEs, malware feeds, artifact integrity, installed code, dependency reachability,
and compatibility are not checked yet.

Lockfiles describe intended package identities, not trusted evidence of the code
on disk. Private/custom packages can share names with public packages and cause
misleading advisory matches. Git/local npm dependencies and Composer development
branches are reported as incomplete coverage. Yarn, pnpm, Bun, npm shrinkwrap, and
npm v1 locks are detected but not supported. A missing lockfile is never treated
as a complete dependency inventory.

Workspace manifests without their own lockfile currently produce conservative
missing-lockfile warnings, even when a root npm lock covers them. Improving that
recognition is tracked in [issue #3](https://github.com/phcodesage/depguard/issues/3).

DepGuard never runs project scripts, installs dependencies, changes manifests,
or performs upgrades. A report with no advisory matches is not a malware verdict
or a security certification. Changing application dependencies does not patch
the PHP/Node runtime serving the application.

## Privacy and network use

`inventory` operates locally and makes no network requests. `scan` sends **all
collected package names, ecosystems, and versions, including private package
names**, to `https://api.osv.dev/v1/querybatch`. It does not upload source files,
lockfile contents, root paths, or credentials. OSV also receives ordinary network
metadata such as your IP address. Only use online scanning where this disclosure
is acceptable. There is no telemetry, account, token, or paid service requirement.

Reports contain local paths and package names. Review them before publishing.
The default total lookup timeout is two minutes; use `--timeout 5m` to adjust it.
HTTP errors and timeouts produce incomplete reports; automatic retries and
offline advisory caching are future work.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Dependency inventory complete; requested advisory lookups completed with no matches. For `inventory`, advisories were not requested. |
| `1` | Known advisory matches found and dependency inventory/lookups completed. |
| `2` | Invalid usage, incomplete inventory, failed lookup, or another error. Takes precedence over code 1; any known findings remain in the report. |

“Complete” here refers only to supported dependency metadata and requested OSV
lookups. The limitations above still apply. JSON reports include
`schema_version`, `inventory_status`, `advisory_status`, `issues`, and `limitations`.

## Contribute

Everyone is welcome to contribute: code, fixtures, documentation, accessibility
improvements, bug reports, and design feedback all help.

1. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
2. Pick a [good first issue](https://github.com/phcodesage/depguard/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22)
   or propose an idea in [Discussions](https://github.com/phcodesage/depguard/discussions).
3. Fork the repository, make a focused change, run the checks, and open a pull request.

No contributor agreement or company affiliation is required. Contributions are
reviewed by maintainers under the [MIT license](LICENSE). See
[governance](GOVERNANCE.md) for how decisions and maintainer access work.

Report vulnerabilities in DepGuard through [private security reporting](https://github.com/phcodesage/depguard/security/advisories/new),
not public issues. See [SECURITY.md](SECURITY.md).

## Development

```sh
gofmt -w cmd internal
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/depguard
```

Tests use local HTTP fixtures and require no advisory API or credentials. The Go
module currently uses only the standard library. CI exercises Linux, macOS, and
Windows. The [architecture](docs/ARCHITECTURE.md) describes extension points.

## License

[MIT](LICENSE), copyright 2026 Rechcel Toledo and DepGuard contributors.
Advisory data and external documentation retain their respective licenses.
