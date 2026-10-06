// Command kb-review is the AI review step for knowledge content. It reads
// the list of changed files, validates the content, sends the changed
// entries (as delimited data) and the review rules to a model, and writes
// a verdict (JSON) and a pull request comment (Markdown). It exits 1 when
// the verdict fails or the answer cannot be parsed, 2 on usage or
// configuration errors.
//
// Configuration (flags override the environment):
//
//	KB_REVIEW_PROVIDER   openai (default) or anthropic
//	KB_REVIEW_MODEL      model name (the workflows pass the tier's model)
//	KB_REVIEW_BASE_URL   API base URL (an OpenAI compatible server, or a proxy)
//	OPENAI_API_KEY       key for the openai provider
//	ANTHROPIC_API_KEY    key for the anthropic provider
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openbasalt/knowledge/internal/review"
	"github.com/openbasalt/knowledge/internal/source"
)

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "kb-review:", err)
	}
	os.Exit(code)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run(args []string) (int, error) {
	fs := flag.NewFlagSet("kb-review", flag.ContinueOnError)
	tier := fs.String("tier", "pr", "pr or release")
	provider := fs.String("provider", env("KB_REVIEW_PROVIDER", "openai"), "openai or anthropic")
	model := fs.String("model", os.Getenv("KB_REVIEW_MODEL"), "model name")
	baseURL := fs.String("base-url", os.Getenv("KB_REVIEW_BASE_URL"), "API base URL")
	rulesFile := fs.String("rules", ".github/review-prompt.md", "review rules file (relative to -repo, or absolute)")
	content := fs.String("content", "content", "content directory (relative to -repo)")
	repo := fs.String("repo", ".", "repository root")
	changedFile := fs.String("changed", "", "file with changed paths, one per line (- for stdin)")
	out := fs.String("out", "", "write the verdict JSON here")
	comment := fs.String("comment", "", "write the Markdown comment here")
	dry := fs.Bool("dry-run", false, "print the prompts and exit without calling a model")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *tier != "pr" && *tier != "release" {
		return 2, errors.New("-tier must be pr or release")
	}
	// The workflows pass the rules from the trusted base branch (an
	// absolute path), so a pull request cannot weaken its own review.
	rulesPath := *rulesFile
	if !filepath.IsAbs(rulesPath) {
		rulesPath = filepath.Join(*repo, rulesPath)
	}
	rules, err := os.ReadFile(rulesPath)
	if err != nil {
		return 2, err
	}
	changed, err := readChanged(*changedFile)
	if err != nil {
		return 2, err
	}
	// Structural validation first: a model never sees content that fails it.
	contentDir := filepath.Join(*repo, *content)
	nsDirs, _ := filepath.Glob(filepath.Join(contentDir, "*", "namespace.yaml"))
	var actions []string
	var sources []*source.Source
	for _, nsFile := range nsDirs {
		src, err := source.Load(filepath.Dir(nsFile))
		if err != nil {
			return 1, fmt.Errorf("content does not validate (run kb validate):\n%v", err)
		}
		sources = append(sources, src)
		actions = append(actions, src.Namespace.Actions...)
	}
	units, err := review.Units(*repo, *content, changed)
	if err != nil {
		return 2, err
	}
	if *tier == "release" {
		for _, src := range sources {
			units = append(units, review.Overview(src))
		}
	}
	if *dry {
		fmt.Println(review.SystemPrompt(string(rules)))
		fmt.Println("-----")
		fmt.Println(review.UserPrompt(*tier, actions, units))
		return 0, nil
	}
	if *model == "" || strings.HasPrefix(*model, "CHANGE-ME") {
		return 2, fmt.Errorf("no model configured for the %s tier (set the repository variable)", *tier)
	}
	var p review.Provider
	switch *provider {
	case "openai":
		key := os.Getenv("OPENAI_API_KEY")
		if key == "" {
			return 2, errors.New("OPENAI_API_KEY is not set")
		}
		p = review.OpenAI{BaseURL: *baseURL, APIKey: key}
	case "anthropic":
		key := os.Getenv("ANTHROPIC_API_KEY")
		if key == "" {
			return 2, errors.New("ANTHROPIC_API_KEY is not set")
		}
		p = review.Anthropic{BaseURL: *baseURL, APIKey: key}
	default:
		return 2, fmt.Errorf("unknown provider %q", *provider)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	v, err := review.Run(ctx, review.Config{Provider: p, Model: *model, Tier: *tier, Rules: string(rules), Actions: actions}, units)
	if err != nil {
		// Fail closed, and still leave a comment saying why.
		if *comment != "" {
			msg := fmt.Sprintf("### Content review (%s tier, %s): failed\n\nThe review could not complete: %s\n", *tier, *model, err)
			_ = os.WriteFile(*comment, []byte(msg), 0o644)
		}
		return 1, err
	}
	if *out != "" {
		b, _ := json.MarshalIndent(v, "", " ")
		if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
			return 2, err
		}
	}
	md := review.Markdown(v, *tier, *model)
	if *comment != "" {
		if err := os.WriteFile(*comment, []byte(md), 0o644); err != nil {
			return 2, err
		}
	} else {
		fmt.Print(md)
	}
	if v.Verdict != "pass" {
		return 1, errors.New("review failed")
	}
	return 0, nil
}

func readChanged(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	f := os.Stdin
	if path != "-" {
		var err error
		if f, err = os.Open(path); err != nil {
			return nil, err
		}
		defer f.Close()
	}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			out = append(out, s)
		}
	}
	return out, sc.Err()
}
