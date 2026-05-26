package find

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/weave-agent/weave/sdk"
	"github.com/weave-agent/weave/utils/ripgrep"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {
	tool, err := sdk.GetTool("find", nil)
	require.NoError(t, err)
	assert.Equal(t, "find", tool.Name())
}

func TestDefinition(t *testing.T) {
	tool := &tool{}
	def := tool.Definition()
	assert.Equal(t, "find", def.Name)
	assert.NotNil(t, def.Parameters)
}

func TestGuardianRequestForFind(t *testing.T) {
	req := guardianRequest("/tmp/project")

	assert.True(t, strings.HasPrefix(req.ID, "find-guardian-"))
	assert.Equal(t, "find", req.ToolName)
	assert.Equal(t, sdk.GuardianActionRead, req.Action)
	assert.Equal(t, "/tmp/project", req.Path)
	assert.Equal(t, "Find files in directory", req.Description)
	assert.Equal(t, "find", req.Metadata["operation"])
}

func TestExecuteGuardianReceivesAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "project"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "project", "readable.txt"), []byte("data"), 0o644))

	t.Chdir(dir)

	var gotPath string
	setGuardian(&testGuardian{decideFn: func(_ context.Context, req sdk.GuardianRequest) (sdk.GuardianDecision, error) {
		gotPath = req.Path

		return sdk.GuardianDecision{RequestID: req.ID, Action: sdk.GuardianDecisionAllow}, nil
	}})
	t.Cleanup(func() {
		setGuardian(nil)
	})

	result, err := (&tool{}).Execute(context.Background(), map[string]any{
		"pattern": "*.txt",
		"path":    "./project",
	})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	assert.Equal(t, filepath.Join(dir, "project"), gotPath)
}

func TestExecuteInvalidPatternSkipsGuardian(t *testing.T) {
	dir := t.TempDir()

	var guardianCalled bool

	setGuardian(&testGuardian{decideFn: func(_ context.Context, req sdk.GuardianRequest) (sdk.GuardianDecision, error) {
		guardianCalled = true

		return sdk.GuardianDecision{RequestID: req.ID, Action: sdk.GuardianDecisionAllow}, nil
	}})
	t.Cleanup(func() {
		setGuardian(nil)
	})

	result, err := (&tool{}).Execute(context.Background(), map[string]any{
		"pattern": "[",
		"path":    dir,
	})
	require.NoError(t, err)
	assert.True(t, result.IsError)
	assert.Contains(t, result.Content, "invalid pattern")
	assert.False(t, guardianCalled)
}

func TestExecute(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) string
		args      map[string]any
		wantError bool
		check     func(t *testing.T, result sdk.ToolResult)
	}{
		{
			name:      "missing pattern",
			setup:     func(t *testing.T) string { return "." },
			args:      map[string]any{},
			wantError: true,
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "pattern is required")
			},
		},
		{
			name: "find by extension",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("hello"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "c.go"), []byte("package pkg"), 0o644))

				return dir
			},
			args: map[string]any{"pattern": "*.go"},
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "a.go")
				assert.Contains(t, result.Content, "c.go")
				assert.NotContains(t, result.Content, "b.txt")
			},
		},
		{
			name: "find by name",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("key: val"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o644))

				return dir
			},
			args: map[string]any{"pattern": "config.yaml"},
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "config.yaml")
				assert.NotContains(t, result.Content, "config.json")
			},
		},
		{
			name: "nested match",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				sub := filepath.Join(dir, "sub", "deep")
				require.NoError(t, os.MkdirAll(sub, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(sub, "target.txt"), []byte("found"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "other.go"), []byte("package main"), 0o644))

				return dir
			},
			args: map[string]any{"pattern": "*.txt"},
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "target.txt")
				assert.NotContains(t, result.Content, "other.go")
			},
		},
		{
			name: "no matches",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644))

				return dir
			},
			args: map[string]any{"pattern": "*.xyz"},
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "no files found")
			},
		},
		{
			name:      "nonexistent path",
			setup:     func(t *testing.T) string { return "/nonexistent/path/xyz" },
			args:      map[string]any{"pattern": "*.go", "path": "/nonexistent/path/xyz"},
			wantError: true,
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "error:")
			},
		},
		{
			name: "skips ignored directories",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("git config"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0o644))

				return dir
			},
			args: map[string]any{"pattern": "*"},
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "main.go")
				assert.NotContains(t, result.Content, "config")
			},
		},
		{
			name: "path is a file",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				f := filepath.Join(dir, "file.txt")
				require.NoError(t, os.WriteFile(f, []byte("hi"), 0o644))

				return f
			},
			args:      map[string]any{"pattern": "*.txt"},
			wantError: true,
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "not a directory")
			},
		},
		{
			name: "recursive doublestar pattern",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "src", "pkg"), 0o755))
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "cmd"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "pkg", "main.go"), []byte("package main"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "pkg", "util.go"), []byte("package pkg"), 0o644))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "cmd", "root.go"), []byte("package cmd"), 0o644))

				return dir
			},
			args: map[string]any{"pattern": "**/pkg/*.go"},
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "main.go")
				assert.Contains(t, result.Content, "util.go")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)

			args := tt.args
			if _, ok := args["path"]; !ok {
				args["path"] = path
			}

			result, err := (&tool{}).Execute(context.Background(), args)
			require.NoError(t, err)
			assert.Equal(t, tt.wantError, result.IsError)

			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

func TestExecuteWithGuardian(t *testing.T) {
	tests := []struct {
		name      string
		guardian  sdk.Guardian
		wantError bool
		check     func(t *testing.T, result sdk.ToolResult)
	}{
		{
			name: "allow decision permits find",
			guardian: &testGuardian{decideFn: func(_ context.Context, req sdk.GuardianRequest) (sdk.GuardianDecision, error) {
				assert.Equal(t, "find", req.ToolName)
				assert.Equal(t, sdk.GuardianActionRead, req.Action)

				return sdk.GuardianDecision{RequestID: req.ID, Action: sdk.GuardianDecisionAllow}, nil
			}},
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "readable.txt")
			},
		},
		{
			name: "block decision returns guardian error",
			guardian: &testGuardian{decideFn: func(_ context.Context, req sdk.GuardianRequest) (sdk.GuardianDecision, error) {
				return sdk.GuardianDecision{
					ID:        "decision-1",
					RequestID: req.ID,
					Action:    sdk.GuardianDecisionBlock,
					Reason:    "read blocked",
					Profile:   "locked-down",
				}, nil
			}},
			wantError: true,
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "guardian: blocked")
				assert.Contains(t, result.Content, "action: read")
				assert.Contains(t, result.Content, "rule: locked-down")
				assert.Contains(t, result.Content, "reason: read blocked")
			},
		},
		{
			name: "missing guardian permits find",
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "readable.txt")
			},
		},
		{
			name: "guardian error returns tool error",
			guardian: &testGuardian{decideFn: func(context.Context, sdk.GuardianRequest) (sdk.GuardianDecision, error) {
				return sdk.GuardianDecision{}, errors.New("guardian unavailable")
			}},
			wantError: true,
			check: func(t *testing.T, result sdk.ToolResult) {
				assert.Contains(t, result.Content, "guardian: guardian unavailable")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "readable.txt"), []byte("data"), 0o644))

			setGuardian(tt.guardian)
			t.Cleanup(func() {
				setGuardian(nil)
			})

			result, err := (&tool{}).Execute(context.Background(), map[string]any{
				"pattern": "*.txt",
				"path":    dir,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.wantError, result.IsError)

			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

func TestExecuteGuardianUnresolvedDecisionBlocks(t *testing.T) {
	tests := []struct {
		name     string
		decision sdk.GuardianDecisionAction
	}{
		{name: "ask decision blocks", decision: sdk.GuardianDecisionAsk},
		{name: "unknown decision blocks", decision: sdk.GuardianDecisionAction("review")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "readable.txt"), []byte("data"), 0o644))

			setGuardian(&testGuardian{decideFn: func(_ context.Context, req sdk.GuardianRequest) (sdk.GuardianDecision, error) {
				return sdk.GuardianDecision{RequestID: req.ID, Action: tt.decision}, nil
			}})
			t.Cleanup(func() {
				setGuardian(nil)
			})

			result, err := (&tool{}).Execute(context.Background(), map[string]any{
				"pattern": "*.txt",
				"path":    dir,
			})
			require.NoError(t, err)
			assert.True(t, result.IsError)
			assert.Contains(t, result.Content, "guardian: blocked")
			assert.Contains(t, result.Content, "reason: guardian returned unresolved approval decision")
		})
	}
}

func TestBusRegistrationHandlers(t *testing.T) {
	bus := &testBus{handlers: map[string][]sdk.Handler{}}
	registerBusHandlers(bus)

	guardian := &testGuardian{}

	bus.Publish(sdk.Event{Topic: sdk.GuardianRegisteredTopic, Payload: "not a guardian"})
	assert.Nil(t, getGuardian())

	bus.Publish(sdk.Event{Topic: sdk.GuardianRegisteredTopic, Payload: guardian})
	t.Cleanup(func() {
		setGuardian(nil)
	})

	assert.Same(t, guardian, getGuardian())
}


func TestRespectGitignore(t *testing.T) {
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("rg not in PATH")
	}

	dir := t.TempDir()

	// Initialize git repo so rg picks up .gitignore
	require.NoError(t, exec.Command("git", "init", dir).Run())
	require.NoError(t, exec.Command("git", "-C", dir, "config", "user.email", "test@test.com").Run())
	require.NoError(t, exec.Command("git", "-C", dir, "config", "user.name", "test").Run())

	require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("ignored.txt\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("ignored"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "visible.txt"), []byte("visible"), 0o644))

	// Stage .gitignore so rg recognizes the repo properly
	require.NoError(t, exec.Command("git", "-C", dir, "add", ".gitignore").Run())
	require.NoError(t, exec.Command("git", "-C", dir, "commit", "-m", "init").Run())

	// With respect_gitignore=true (default), ignored.txt should be excluded
	cfg := &testConfig{respectGitignore: true}
	tt := &tool{cfg: cfg}

	result, err := tt.Execute(context.Background(), map[string]any{
		"pattern": "*.txt",
		"path":    dir,
	})
	require.NoError(t, err)
	assert.Contains(t, result.Content, "visible.txt")
	assert.NotContains(t, result.Content, "ignored.txt")

	// With respect_gitignore=false, ignored.txt should be included
	cfg.respectGitignore = false

	result, err = tt.Execute(context.Background(), map[string]any{
		"pattern": "*.txt",
		"path":    dir,
	})
	require.NoError(t, err)
	assert.Contains(t, result.Content, "visible.txt")
	assert.Contains(t, result.Content, "ignored.txt")
}

func TestRgFallback(t *testing.T) {
	// Force fallback by providing an invalid rg path
	origFind := ripgrep.Find
	ripgrep.Find = func() string { return "" }

	t.Cleanup(func() { ripgrep.Find = origFind })

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), []byte("hello"), 0o644))

	result, err := (&tool{}).Execute(context.Background(), map[string]any{
		"pattern": "*.go",
		"path":    dir,
	})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	assert.Contains(t, result.Content, "a.go")
	assert.NotContains(t, result.Content, "b.txt")
}

func TestRgPathDirect(t *testing.T) {
	// Test the rg path directly when rg is available
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("rg not in PATH")
	}

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "main.go"), []byte("package main"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# hello"), 0o644))

	result, err := (&tool{}).Execute(context.Background(), map[string]any{
		"pattern": "*.go",
		"path":    dir,
	})
	require.NoError(t, err)
	assert.Contains(t, result.Content, "main.go")
	assert.NotContains(t, result.Content, "readme.md")
}

func TestDoubleStarPatternWithSlash(t *testing.T) {
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("rg not in PATH")
	}

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src", "pkg"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src", "pkg", "handler.go"), []byte("package pkg"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lib", "handler.go"), []byte("package lib"), 0o644))

	result, err := (&tool{}).Execute(context.Background(), map[string]any{
		"pattern": "**/pkg/*.go",
		"path":    dir,
	})
	require.NoError(t, err)
	assert.Contains(t, result.Content, "pkg")
	assert.Contains(t, result.Content, "handler.go")
	assert.NotContains(t, result.Content, "lib")
}

type testConfig struct {
	respectGitignore bool
}

func (c *testConfig) FilePath() string                         { return "" }
func (c *testConfig) ProjectDir() string                       { return "" }
func (c *testConfig) ExtensionConfig(_, _ string, _ any) error { return nil }
func (c *testConfig) IsHeadless() bool                         { return false }
func (c *testConfig) RespectGitignore() bool                   { return c.respectGitignore }
func (c *testConfig) Preferences(any) error                    { return nil }
func (c *testConfig) SavePreferences(any) error                { return nil }
func (c *testConfig) SaveProviderKey(_, _ string) error        { return nil }

type testGuardian struct {
	decideFn func(context.Context, sdk.GuardianRequest) (sdk.GuardianDecision, error)
}

func (tg *testGuardian) Decide(ctx context.Context, req sdk.GuardianRequest) (sdk.GuardianDecision, error) {
	if tg.decideFn != nil {
		return tg.decideFn(ctx, req)
	}

	return sdk.GuardianDecision{RequestID: req.ID, Action: sdk.GuardianDecisionAllow}, nil
}

func (tg *testGuardian) Resolve(context.Context, string, sdk.GuardianResolution) error {
	return nil
}

func (tg *testGuardian) Snapshot(context.Context) (sdk.GuardianSnapshot, error) {
	return sdk.GuardianSnapshot{}, nil
}

type testBus struct {
	handlers map[string][]sdk.Handler
}

func (tb *testBus) Publish(ev sdk.Event) {
	for _, handler := range tb.handlers[ev.Topic] {
		_ = handler(ev)
	}
}

func (tb *testBus) On(topic string, h sdk.Handler) {
	tb.handlers[topic] = append(tb.handlers[topic], h)
}

func (tb *testBus) OnAll(sdk.Handler) {}
func (tb *testBus) Off(sdk.Handler)   {}
func (tb *testBus) Close() error      { return nil }
