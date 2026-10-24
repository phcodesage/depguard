# Example metadata

`mixed-project/` is a hand-written, metadata-only test fixture. Its npm dependency
is deliberately outdated so an online scan can demonstrate advisory findings.
These files are not a deployable application or package-manager-generated locks.
Do not install them. DepGuard only reads their metadata.

```sh
go run ./cmd/depguard inventory examples/mixed-project
go run ./cmd/depguard scan examples/mixed-project
```

The online command sends the example package identity to OSV and should exit 1
when advisory matches are returned. Results depend on the current advisory feed.
