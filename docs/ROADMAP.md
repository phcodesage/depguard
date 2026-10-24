# Roadmap

This is a direction for community discussion, not a delivery schedule. Open an
issue or discussion before taking on broad architectural work.

## Available now

- [x] Read-only npm lockfile v2/v3 and Composer inventory, including dev dependencies.
- [x] Known dependency advisory lookups through OSV with batching and pagination.
- [x] Runtime declaration inventory with explicit unverified status.
- [x] Text/JSON output, incomplete coverage reporting, and CI exit codes.
- [x] Local tests, cross-platform CI, contribution guidance, and MIT licensing.

## Improve scanning

- [ ] Parser fixtures for more real-world projects, with identities sanitized.
- [ ] npm v1, shrinkwrap, pnpm, Yarn, and Bun adapters.
- [ ] Structured dependency paths and direct/transitive classification.
- [ ] Advisory details, withdrawn-advisory handling, severity, and fixed-version evidence.
- [ ] Explicit private package exclusions and configurable trusted advisory sources.
- [ ] Retries with backoff, rate-limit handling, and an offline advisory cache with freshness metadata.
- [ ] SARIF reports and stable JSON schema documentation.
- [ ] Native runtime advisory sources, supported-version schedules, Docker/CI discovery,
      and explicit deployed-version evidence with vendor backport awareness.
- [ ] Packagist malware metadata and other transparently sourced malware signals.

## Plan upgrades

- [ ] `plan` command with separate security-fix and latest-compatible policies.
- [ ] Registry metadata adapters, release timestamps, and candidate advisory checks.
- [ ] Compatibility resolution using package-manager constraints and platform requirements.
- [ ] Configurable cooldowns applied to every newly resolved dependency, with an
      explicit urgent-security exception policy and missing-timestamp behavior.
- [ ] Plans that show exact changes, provenance, unresolved risks, and advisory evidence.

## Apply and verify

- [ ] `apply` command restricted to an isolated checkout with a versioned plan.
- [ ] Native lockfile generation with installation scripts and Composer plugins disabled.
- [ ] Re-scan the complete resulting dependency graph before accepting changes.
- [ ] Separate sandboxed builds/tests with no production credentials.
- [ ] Pull request creation with advisory links, validation results, and rollback guidance.
- [ ] Signed releases, checksums, and reproducible distribution artifacts.

“Latest,” provenance, popularity, and an absence of advisory matches are individual
signals; none should be presented as a guarantee that a package is safe.
