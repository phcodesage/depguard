# Contributing to DepGuard

All experience levels are welcome. You can contribute code, documentation,
sanitized lockfile fixtures, bug reports, translations, or design feedback.
Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Get started

1. Fork the repository and clone your fork.
2. Install Go 1.25 or newer.
3. Create a branch: `git switch -c fix/short-description`.
4. Run `go test ./...` to establish a baseline.

There are no service credentials or third-party Go modules to configure. Unit
tests use local HTTP servers. Never install intentionally vulnerable example
packages to test the scanner.

## Choose work

Check [open issues](https://github.com/phcodesage/depguard/issues), especially
`good first issue` and `help wanted`, or open a discussion for a larger change.
You may comment that you are working on an issue; no permission is needed to
start a focused contribution. Maintainers may suggest coordination if someone
else is already working on it.

Documentation and small fixes can go directly to a pull request. Discuss changes
to update execution, network behavior, report schemas, and new dependencies
first so maintainers and contributors can agree on scope.

## Checks before a pull request

```sh
gofmt -w cmd internal
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/depguard
```

For behavior changes, add tests that demonstrate the problem and protect useful
behavior. Parser tests should cover both valid metadata and incomplete coverage.
Network tests must use local HTTP fixtures; normal CI must not rely on OSV being
available. Update user documentation when behavior or output changes.

Keep pull requests focused. Explain the problem, resulting behavior, checks
performed, and any remaining limitations. Include screenshots only when useful.
Generated files or changes to report schema should be called out explicitly.

## Security and privacy

- Treat target files and advisory responses as untrusted input.
- Preserve the distinction between no known findings and an incomplete scan.
- Never run target project code during inventory or advisory lookup.
- Do not add source uploads, telemetry, or credential access without discussing
  the concrete need and documenting what leaves the machine.
- Remove secrets, personal paths, and private package names from shared fixtures.
- Report vulnerabilities in DepGuard privately using [SECURITY.md](SECURITY.md).

## Review and licensing

Maintainers review contributions for correctness, scope, usability, and safety.
Review may request changes; opening a pull request does not guarantee a merge.
Constructive disagreements are welcome and should focus on evidence and behavior.

By submitting a contribution, you agree that it is provided under this project's
[MIT license](LICENSE). Keep attribution and license notices for any reused work.
There is no CLA, DCO sign-off requirement, or organization membership requirement.

See [GOVERNANCE.md](GOVERNANCE.md) for project decisions and maintainer roles.
