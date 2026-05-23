# Guardian Integration for find Tool

## Overview
Add guardian policy enforcement to the `find` tool so that filesystem traversal is subject to the guardian's allow/ask/block decisions. The `find` tool searches directories — this is a `GuardianActionRead` action.

## Context
- **Tool file**: `find.go`
- **Test file**: `find_test.go`
- **Reference pattern**: `weave-bash` extension (`bash.go` lines 68-317)
- **Guardian action**: `sdk.GuardianActionRead`
- The find tool already has sandbox integration (`sandboxer.AllowRead(absPath)` at line 106); guardian must run *before* sandbox.
- Note: `ask` profile auto-allows reads, but custom profiles may block or log them.

## Development Approach
- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- Make small, focused changes
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- Run tests after each change

## Testing Strategy
- **Unit tests**: mock guardian with allow/block/ask/error decisions
- Verify guardian check runs before sandbox check
- Verify guardian block skips sandbox and returns error result
- Verify guardian allow proceeds to sandbox and find logic

## Implementation Steps

### Task 1: Add guardian infrastructure to find.go
- [x] Add `guardianMu sync.RWMutex`, `guardian sdk.Guardian` package-level variables
- [x] Add `setGuardian()` / `getGuardian()` helpers
- [x] Add `GuardianRegisteredTopic` listener in `init()` alongside existing `sandbox.registered` listener
- [x] Add `newRequestID()` helper
- [x] Add `guardianRequest(path string) sdk.GuardianRequest` helper with `Action: sdk.GuardianActionRead`
- [x] Add `checkGuardian()` helper (same pattern as bash)
- [x] Add `formatGuardianBlock()` helper (same as bash)
- [x] Call `checkGuardian()` at start of `Execute()`, before directory traversal and sandbox checks
- [x] Pass `guardianReq.ID` into sandbox metadata for linkage
- [x] Run find tests — must pass before next task

### Task 2: Add guardian tests to find_test.go
- [x] Write `TestExecuteWithGuardian` with subtests:
  - "allow decision permits find"
  - "block decision returns guardian error"
  - "missing guardian permits find"
  - "guardian error returns tool error"
- [x] Write `TestExecuteGuardianSandboxOrdering`:
  - "guardian allow runs before sandbox"
  - "guardian block skips sandbox"
- [x] Add `testGuardian` mock helper
- [x] Run find tests — must pass

### Task 3: Verify and cleanup
- [ ] Run `make lint` in find extension directory
- [ ] Run full test suite for find extension
- [ ] Verify no regressions in existing find functionality

## Technical Details

### guardianRequest for find
```go
func guardianRequest(path string) sdk.GuardianRequest {
    return sdk.GuardianRequest{
        ID:          newRequestID("find-guardian"),
        ToolName:    "find",
        Action:      sdk.GuardianActionRead,
        Path:        path,
        Description: "Find files in directory",
        Metadata: map[string]any{
            "operation": "find",
        },
    }
}
```

### Execute ordering
1. Validate `path` parameter
2. **Guardian check** (`checkGuardian`) — if blocked, return error
3. Resolve and validate directory path
4. Sandbox check (`sandboxer.AllowRead`)
5. Walk directory, collect results

## Post-Completion
- Manual verification: test find tool with `ask` profile — should auto-allow reads
- Test with custom profile that blocks reads — should block
