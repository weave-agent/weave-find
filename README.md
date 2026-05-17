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

## Development

```bash
git clone git@github.com:weave-agent/weave-find.git
cd weave-find

# Add temporary replace for local SDK (don't commit this)
echo 'replace github.com/weave-agent/weave => /path/to/local/weave' >> go.mod

go test ./...
```

## License

Same as the main weave project.
