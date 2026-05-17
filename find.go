package find

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/weave-agent/weave/sdk"
	"github.com/weave-agent/weave/utils/ripgrep"
	"github.com/weave-agent/weave/utils/truncate"
)

// ParamPattern is the tool parameter name for the glob pattern.
const ParamPattern = "pattern"

const paramPath = "path"

type tool struct {
	cfg sdk.Config
}

var (
	sandboxerMu sync.RWMutex
	sandboxer   sdk.Sandboxer
)

func setSandboxer(s sdk.Sandboxer) {
	sandboxerMu.Lock()
	sandboxer = s
	sandboxerMu.Unlock()
}

func getSandboxer() sdk.Sandboxer {
	sandboxerMu.RLock()

	s := sandboxer

	sandboxerMu.RUnlock()

	return s
}

func init() {
	sdk.OnBusReady(func(bus sdk.Bus) {
		bus.On("sandbox.registered", func(ev sdk.Event) error {
			if s, ok := ev.Payload.(sdk.Sandboxer); ok {
				setSandboxer(s)
			}

			return nil
		})
	})

	sdk.RegisterTool[struct{}]("find", func(cfg sdk.Config, _ sdk.PreferenceReader, _ struct{}) (sdk.Tool, error) {
		return &tool{cfg: cfg}, nil
	})
}

func (t *tool) Name() string { return "find" }

func (t *tool) Definition() sdk.ToolDef {
	return sdk.ToolDef{
		Name:        "find",
		Description: "Find files matching a glob pattern. Uses ripgrep when available for .gitignore support and faster searches; falls back to pure Go when rg is absent. Supports **/ recursive patterns.",
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				ParamPattern: map[string]any{
					"type":        "string",
					"description": "Glob pattern to match against file names (e.g. \"*.go\", \"config.yaml\", \"src/**/*.go\").",
				},
				paramPath: map[string]any{
					"type":        "string",
					"description": "Directory to search in. Defaults to current directory.",
				},
			},
			"required":             []string{ParamPattern},
			"additionalProperties": false,
		},
	}
}

func (t *tool) Execute(ctx context.Context, args map[string]any) (sdk.ToolResult, error) {
	pattern, _ := args[ParamPattern].(string)
	if pattern == "" {
		return sdk.ToolResult{Content: "error: pattern is required", IsError: true}, nil
	}

	path, _ := args[paramPath].(string)
	if path == "" {
		path = "."
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return sdk.ToolResult{Content: fmt.Sprintf("error: %s", err), IsError: true}, nil
	}

	if s := getSandboxer(); s != nil && !s.AllowRead(absPath) {
		return sdk.ToolResult{Content: "sandbox: read denied — path is protected", IsError: true}, nil
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return sdk.ToolResult{Content: fmt.Sprintf("error: %s", err), IsError: true}, nil
	}

	if !info.IsDir() {
		return sdk.ToolResult{Content: fmt.Sprintf("error: %s is not a directory", absPath), IsError: true}, nil
	}

	if _, validateErr := filepath.Match(pattern, ""); validateErr != nil {
		return sdk.ToolResult{Content: fmt.Sprintf("error: invalid pattern: %s", validateErr), IsError: true}, nil
	}

	respectGitignore := true
	if t.cfg != nil {
		respectGitignore = t.cfg.RespectGitignore()
	}

	matches := t.find(ctx, absPath, pattern, respectGitignore)

	if len(matches) == 0 {
		return sdk.ToolResult{Content: "no files found", IsError: false}, nil
	}

	output := strings.Join(matches, "\n")
	result := truncate.Truncate(output, truncate.DefaultMaxLines, truncate.DefaultMaxBytes)

	return sdk.ToolResult{Content: result.Format(), IsError: false}, nil
}

// find tries rg first, then falls back to stdlib.
func (t *tool) find(ctx context.Context, absPath, pattern string, respectGitignore bool) []string {
	// Use rg when available. Denied paths are filtered from results by
	// AllowRead checks in filterResults.
	if rgPath := ripgrep.Find(); rgPath != "" {
		matches, err := findWithRipgrep(ctx, rgPath, absPath, pattern, respectGitignore)
		if err == nil {
			return matches
		}
	}

	return findWithStdlib(absPath, pattern, respectGitignore)
}

func findWithRipgrep(ctx context.Context, rgPath, absPath, pattern string, respectGitignore bool) ([]string, error) {
	args := []string{"--files", "--null", "--hidden"}

	if !respectGitignore {
		args = append(args, "--no-ignore")
	}

	args = append(args, ".")

	cmd := exec.CommandContext(ctx, rgPath, args...)
	cmd.Dir = absPath

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rg: %w", err)
	}

	return filterResults(out, absPath, pattern, respectGitignore)
}

// filterResults parses null-separated rg output, applies glob matching and skip-dir filtering.
func filterResults(data []byte, baseDir, pattern string, respectGitignore bool) ([]string, error) {
	var matches []string

	entries := bytes.SplitSeq(data, []byte{0})

	for entry := range entries {
		text := strings.TrimSpace(string(entry))
		if text == "" {
			continue
		}

		// rg outputs paths relative to its CWD (baseDir), so clean the relative path directly
		rel := filepath.Clean(text)

		// Skip VCS and dependency directories (matches stdlib isSkipDir behavior)
		if respectGitignore && isSkipPath(rel) {
			continue
		}

		if s := getSandboxer(); s != nil && !s.AllowRead(filepath.Join(baseDir, text)) {
			continue
		}

		name := filepath.Base(text)
		if matchName(pattern, name, rel) {
			matches = append(matches, rel)
		}
	}

	return matches, nil
}

// isSkipPath returns true if the relative path is under a VCS or dependency directory.
func isSkipPath(rel string) bool {
	return slices.ContainsFunc(strings.Split(rel, string(filepath.Separator)), isSkipDir)
}

func findWithStdlib(absPath, pattern string, respectGitignore bool) []string {
	var matches []string

	err := filepath.WalkDir(absPath, func(walkPath string, d fs.DirEntry, walkErr error) error {
		//nolint:nilerr // walkErr/relErr are intentionally swallowed to skip inaccessible paths
		if walkErr != nil {
			return nil
		}

		rel, relErr := filepath.Rel(absPath, walkPath)
		if relErr != nil {
			return nil //nolint:nilerr // relErr intentionally swallowed to skip inaccessible paths
		}

		if d.IsDir() {
			name := d.Name()
			if respectGitignore && isSkipDir(name) {
				return filepath.SkipDir
			}

			if rel != "." && matchName(pattern, name, rel) && allowRead(walkPath) {
				matches = append(matches, rel)
			}

			return nil
		}

		if matchName(pattern, d.Name(), rel) && allowRead(walkPath) {
			matches = append(matches, rel)
		}

		return nil
	})
	if err != nil {
		return nil
	}

	return matches
}

func matchName(pattern, name, rel string) bool {
	// Try exact match against filename
	matched, _ := filepath.Match(pattern, name)
	if matched {
		return true
	}

	// Try match against relative path
	matched, _ = filepath.Match(pattern, rel)
	if matched {
		return true
	}

	// Handle **/ patterns: "**/pkg/*.go" matches "src/pkg/main.go"
	if strings.Contains(pattern, "**/") {
		return matchDoubleStar(pattern, rel)
	}

	return false
}

func matchDoubleStar(pattern, rel string) bool {
	// Split pattern into parts separated by **
	// e.g. "src/**/*.go" -> ["src/", "*.go"]
	// e.g. "**/pkg/*.go" -> ["", "pkg/*.go"]
	parts := strings.SplitN(pattern, "**/", 2)
	if len(parts) != 2 {
		return false
	}

	prefix := parts[0]
	suffix := parts[1]

	relParts := strings.Split(rel, string(filepath.Separator))

	suffixParts := strings.Split(suffix, "/")
	if len(suffixParts) == 0 {
		return false
	}

	// Match prefix against leading path components
	if prefix != "" {
		prefixParts := strings.Split(strings.TrimSuffix(prefix, "/"), "/")
		if len(relParts) < len(prefixParts) {
			return false
		}

		for i, pp := range prefixParts {
			matched, _ := filepath.Match(pp, relParts[i])
			if !matched {
				return false
			}
		}

		// Consume prefix parts and try matching suffix at every remaining position
		relParts = relParts[len(prefixParts):]
	}

	// Try matching suffix at each position
	for start := 0; start <= len(relParts)-len(suffixParts); start++ {
		allMatch := true

		for i, sp := range suffixParts {
			matched, _ := filepath.Match(sp, relParts[start+i])
			if !matched {
				allMatch = false
				break
			}
		}

		if allMatch {
			return true
		}
	}

	return false
}

func isSkipDir(name string) bool {
	return name == ".git" || name == "node_modules" || name == ".hg" || name == ".svn"
}

func allowRead(path string) bool {
	if s := getSandboxer(); s != nil {
		return s.AllowRead(path)
	}

	return true
}
