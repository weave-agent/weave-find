# CLAUDE.md

## Guardian/Sandbox Integration

- Register runtime integrations through `registerBusHandlers`, which listens for `sdk.GuardianRegisteredTopic` and `sdk.SandboxRegisteredTopic`.
- Guardian checks run after lexical absolute-path normalization and before sandbox expansion and traversal.
- `find` uses `sdk.GuardianActionRead`; unresolved guardian decisions, including `ask`, are treated as blocks.
- Sandbox access uses `sdk.Sandboxer.RequestExpansion`, not a direct read predicate.
- Root sandbox denial returns a tool error. Per-result sandbox denial filters that result from ripgrep and stdlib output.
- Request IDs use `find-guardian-*` and `find-sandbox-*` prefixes. Sandbox expansion metadata includes `guardian_request_id`.

## Build and Test

- Run `go test ./...` for the extension test suite.
- Run `go vet ./...` for static checks.
- There is no Makefile lint target in this extension.

## Testing Conventions

- Tests that set package-level guardian or sandboxer state must clean it up with `t.Cleanup`.
- Cover both ripgrep and forced-stdlib paths when changing traversal or sandbox filtering behavior.
- Use test doubles for `RequestExpansion` and `Decide`; unused interface methods should stay fixed no-op/default implementations.
