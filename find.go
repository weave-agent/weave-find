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
	"sync/atomic"

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
	guardianMu  sync.RWMutex
	guardian    sdk.Guardian
	requestSeq  atomic.Uint64
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

func setGuardian(g sdk.Guardian) {
	guardianMu.Lock()
	guardian = g
	guardianMu.Unlock()
}

func getGuardian() sdk.Guardian {
	guardianMu.RLock()

	g := guardian

	guardianMu.RUnlock()

	return g
}

func registerBusHandlers(bus sdk.Bus) {
	bus.On(sdk.GuardianRegisteredTopic, func(ev sdk.Event) error {
		if g, ok := ev.Payload.(sdk.Guardian); ok {
			setGuardian(g)
		}

		return nil
	})

	bus.On(sdk.SandboxRegisteredTopic, func(ev sdk.Event) error {
		if s, ok := ev.Payload.(sdk.Sandboxer); ok {
			setSandboxer(s)
		}

		return nil
	})
}

func init() {
	sdk.OnBusReady(func(bus sdk.Bus) {
		registerBusHandlers(bus)
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

func newRequestID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, requestSeq.Add(1))
}

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

func checkGuardian(ctx context.Context, path string) (sdk.GuardianRequest, *sdk.ToolResult) {
	req := guardianRequest(path)

	g := getGuardian()
	if g == nil {
		return req, nil
	}

	decision, err := g.Decide(ctx, req)
	if err != nil {
		return req, &sdk.ToolResult{Content: "guardian: " + err.Error(), IsError: true}
	}

	switch decision.Action {
	case sdk.GuardianDecisionAllow:
		return req, nil
	case sdk.GuardianDecisionBlock:
		return req, &sdk.ToolResult{Content: formatGuardianBlock(req, decision), IsError: true}
	default:
		decision.Action = sdk.GuardianDecisionBlock
		if decision.Reason == "" {
			decision.Reason = "guardian returned unresolved approval decision"
		}

		return req, &sdk.ToolResult{Content: formatGuardianBlock(req, decision), IsError: true}
	}
}

func formatGuardianBlock(req sdk.GuardianRequest, decision sdk.GuardianDecision) string {
	var b strings.Builder

	b.WriteString("guardian: blocked")
	b.WriteString("\naction: ")
	b.WriteString(string(req.Action))

	rule := decision.Profile
	if rule == "" {
		rule = decision.MatchedGrantID
	}
	if rule == "" {
		rule = decision.ID
	}
	if rule != "" {
		b.WriteString("\nrule: ")
		b.WriteString(rule)
	}

	if decision.Reason != "" {
		b.WriteString("\nreason: ")
		b.WriteString(decision.Reason)
	}

	return b.String()
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

	guardianReq, guardianResult := checkGuardian(ctx, absPath)
	if guardianResult != nil {
		return *guardianResult, nil
	}

	readChecker := newSandboxReadChecker(ctx, guardianReq.ID)
	if allowed, reason := readChecker.Allow(absPath); !allowed {
		return sdk.ToolResult{Content: formatSandboxDenied(reason), IsError: true}, nil
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

	matches := t.find(ctx, absPath, pattern, respectGitignore, readChecker)

	if len(matches) == 0 {
		return sdk.ToolResult{Content: "no files found", IsError: false}, nil
	}

	output := strings.Join(matches, "\n")
	result := truncate.Truncate(output, truncate.DefaultMaxLines, truncate.DefaultMaxBytes)

	return sdk.ToolResult{Content: result.Format(), IsError: false}, nil
}

// find tries rg first, then falls back to stdlib.
func (t *tool) find(ctx context.Context, absPath, pattern string, respectGitignore bool, readChecker sandboxReadChecker) []string {
	// Use rg when available and sandboxing is inactive. With sandboxing active,
	// stdlib traversal can skip denied directories before descending.
	if rgPath := ripgrep.Find(); rgPath != "" && !readChecker.Active() {
		matches, err := findWithRipgrep(ctx, rgPath, absPath, pattern, respectGitignore, readChecker.Allow)
		if err == nil {
			return matches
		}
	}

	return findWithStdlib(ctx, absPath, pattern, respectGitignore, readChecker.Allow)
}

func findWithRipgrep(ctx context.Context, rgPath, absPath, pattern string, respectGitignore bool, allowRead func(string) (bool, string)) ([]string, error) {
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

	return filterResults(out, absPath, pattern, respectGitignore, allowRead)
}

// filterResults parses null-separated rg output, applies glob matching and skip-dir filtering.
func filterResults(data []byte, baseDir, pattern string, respectGitignore bool, allowRead func(string) (bool, string)) ([]string, error) {
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

		name := filepath.Base(text)
		if matchName(pattern, name, rel) {
			if allowed, _ := allowRead(filepath.Join(baseDir, text)); !allowed {
				continue
			}

			matches = append(matches, rel)
		}
	}

	return matches, nil
}

// isSkipPath returns true if the relative path is under a VCS or dependency directory.
func isSkipPath(rel string) bool {
	return slices.ContainsFunc(strings.Split(rel, string(filepath.Separator)), isSkipDir)
}

func findWithStdlib(ctx context.Context, absPath, pattern string, respectGitignore bool, allowRead func(string) (bool, string)) []string {
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
			if rel != "." {
				if allowed, _ := allowRead(walkPath); !allowed {
					return filepath.SkipDir
				}
			}

			name := d.Name()
			if respectGitignore && isSkipDir(name) {
				return filepath.SkipDir
			}

			if rel != "." && matchName(pattern, name, rel) {
				if allowed, _ := allowRead(walkPath); allowed {
					matches = append(matches, rel)
				}
			}

			return nil
		}

		if matchName(pattern, d.Name(), rel) {
			if allowed, _ := allowRead(walkPath); allowed {
				matches = append(matches, rel)
			}
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

type sandboxReadChecker struct {
	active bool
	allow  func(string) (bool, string)
}

func (src sandboxReadChecker) Active() bool {
	return src.active
}

func (src sandboxReadChecker) Allow(path string) (bool, string) {
	return src.allow(path)
}

func newSandboxReadChecker(ctx context.Context, guardianRequestID string) sandboxReadChecker {
	s := getSandboxer()
	if s == nil {
		return sandboxReadChecker{allow: func(string) (bool, string) { return true, "" }}
	}

	return sandboxReadChecker{active: true, allow: func(path string) (bool, string) {
		expansion, err := s.RequestExpansion(ctx, sdk.SandboxExpansionRequest{
			ID:      newRequestID("find-sandbox"),
			Command: "find",
			Reason:  "Find files in directory",
			Filesystem: []sdk.SandboxFilesystemExpansion{
				{Path: path, Access: sdk.SandboxFilesystemRead},
			},
			Metadata: map[string]any{
				"operation":           "find",
				"guardian_request_id": guardianRequestID,
			},
		})
		if err != nil {
			return false, err.Error()
		}

		if expansion.State == sdk.SandboxExpansionAllowed {
			return true, ""
		}

		if expansion.Reason != "" {
			return false, expansion.Reason
		}
		if expansion.Resolution != nil && expansion.Resolution.Reason != "" {
			return false, expansion.Resolution.Reason
		}
		if expansion.State != "" {
			return false, "sandbox expansion " + string(expansion.State)
		}

		return false, ""
	}}
}

func formatSandboxDenied(reason string) string {
	if reason == "" {
		return "sandbox: read denied — path is protected"
	}

	return "sandbox: read denied — path is protected\nreason: " + reason
}
