# weave-find

Find tool extension for [weave](https://github.com/weave-agent/weave) — an event-driven coding agent framework.

## Fork & Customize

1. Fork this repo
2. Edit the extension implementation
3. Install your fork: `weave install github.com/<you>/weave-find --name find`

The `--name find` ensures your fork shadows the official extension.

## Install

```bash
weave install github.com/weave-agent/weave-find --name find
```

## Behavior

`find` searches a directory for files matching a glob pattern. It uses `rg`
when available and falls back to the Go standard library walker when `rg` is
absent or fails.

When a guardian is registered, `find` sends an `sdk.GuardianActionRead` request
before resolving or traversing the directory. Allow decisions continue the
search, block decisions return `guardian: blocked`, unresolved ask decisions are
treated as blocks, and guardian errors return a tool error. If no guardian is
registered, the search is permitted to continue.

When a sandboxer is registered, `find` checks read access with
`sdk.Sandboxer.RequestExpansion`. A denied root directory returns
`sandbox: read denied — path is protected`; denied per-result paths are filtered
from the returned matches. Sandbox expansion metadata includes the related
`guardian_request_id` for correlation.

## Development

```bash
git clone git@github.com:weave-agent/weave-find.git
cd weave-find

# Add temporary replace for local SDK (don't commit this)
echo 'replace github.com/weave-agent/weave => /path/to/local/weave' >> go.mod

go test ./...
go vet ./...
```

## License

Same as the main weave project.
