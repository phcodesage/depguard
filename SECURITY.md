# Security policy

## Supported versions

DepGuard is in early development. Security fixes are developed on `main`; there
are no stable releases or older maintained release branches yet. Run the latest
reviewed commit and consult the repository's security advisories.

## Report a vulnerability in DepGuard

Use [GitHub private vulnerability reporting](https://github.com/phcodesage/depguard/security/advisories/new).
Do not disclose an unpatched vulnerability through a public issue or discussion.

Include the affected commit, platform, minimal sanitized reproduction, expected
and actual behavior, and the potential impact. Avoid sending live secrets,
production data, or malware. Use inert fixtures wherever possible.

There is no paid bug bounty or guaranteed response time. The maintainer will
review reports as availability permits and coordinate a fix and disclosure with
the reporter. Please keep details private while remediation is coordinated.

## Reports about other packages

For a vulnerable dependency, follow that package's reporting policy. A DepGuard
match links to an existing public OSV advisory; DepGuard is not an advisory
authority. If the scanner misidentifies a package or reports incomplete coverage
incorrectly, open a sanitized bug report unless the issue itself is exploitable.

## Current boundaries

DepGuard reads metadata and queries OSV. It does not run target scripts or install
packages. Online scans disclose package names and versions to OSV, including
private package names. Reports can contain local paths. Runtime CVEs, unknown
malware, installed artifacts, and automatic remediation are outside current
coverage. See the README for details.
