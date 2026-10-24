# Architecture

DepGuard is a Go CLI with no third-party Go modules. The initial implementation
separates project parsing, advisory transport, the report model, and CLI behavior.

| Path | Responsibility |
| --- | --- |
| `cmd/depguard` | Commands, flags, terminal/JSON output, cancellation, exit codes |
| `internal/inventory` | Recursive discovery and npm/Composer metadata parsing |
| `internal/advisory` | Bounded, paginated OSV queries and location mapping |
| `internal/model` | Versioned report structures |
| `examples` | Inert demonstration metadata |

## Current flow

1. Resolve the requested root and walk supported metadata files.
2. Extract exact package identities from locks, keeping every installation location.
3. Report unsupported metadata and unqueryable dependencies as incomplete.
4. For `scan`, deduplicate ecosystem/name/version lookups and query OSV in batches
   of at most 100. Follow pagination only for queries that have another page.
5. Map advisory IDs to every matching location, preserving partial findings if
   later requests fail. Advisory detail fetching and fixed-version planning are
   not implemented.
6. Render the report. Exit 2 for incomplete coverage, otherwise 1 for findings,
   otherwise 0. Inventory-only reports explicitly say lookups were not requested.

OSV receives package identities and versions, never local paths or file contents.
There is a per-request timeout, a total lookup deadline, bounded response reads,
and a pagination limit. Redirects are not followed by the production client.
Local tests inject an HTTP fixture endpoint; the CLI has no arbitrary endpoint flag.

## Planned upgrade boundary

Future planning should produce a reviewable, versioned plan separately from
execution. Resolution must use native package managers in an isolated checkout
with hooks/plugins disabled, followed by a scan of the entire resolved graph.
Application builds and tests execute untrusted code and require a separate
sandbox without production secrets. Do not add execution to inventory code.

Version constraints and declared runtimes are evidence about configuration, not
proof of installed or deployed versions. Runtime checks need an explicit source
of deployed-version evidence and vendor-aware handling of backported patches.

## Sources

- [OSV querybatch API and pagination](https://google.github.io/osv.dev/post-v1-querybatch/)
- [npm package-lock format](https://docs.npmjs.com/cli/configuring-npm/package-lock-json)
- [Composer lockfiles](https://getcomposer.org/doc/01-basic-usage.md#installing-dependencies)
