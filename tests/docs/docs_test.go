// Package docs_test checks the operator documentation against the code and against itself.
package docs_test

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const (
	repoRoot      = "../.."
	configDocPath = "docs/configuration.md"
	blobPrefix    = "https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/master/"
	rawPrefix     = "https://raw.githubusercontent.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/master/"
)

// configKeys returns the YAML names of every plugin setting, from the json tags of configuration.Config.
func configKeys(t *testing.T) []string {
	t.Helper()

	configType := reflect.TypeFor[configuration.Config]()
	keys := make([]string, 0, configType.NumField())
	for i := range configType.NumField() {
		name, _, _ := strings.Cut(configType.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		keys = append(keys, name)
	}
	if len(keys) == 0 {
		t.Fatal("configuration.Config has no json-tagged field")
	}

	return keys
}

func readDoc(t *testing.T, rel string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}

	return strings.ReplaceAll(string(content), "\r\n", "\n")
}

// TestConfigurationDocCoversEverySetting fails when a setting is added to configuration.Config
// without its own heading in docs/configuration.md, or when the doc names a setting that no longer exists.
func TestConfigurationDocCoversEverySetting(t *testing.T) {
	doc := readDoc(t, configDocPath)

	headingRe := regexp.MustCompile("(?m)^#### `([A-Za-z]+)`$")
	documented := map[string]bool{}
	for _, match := range headingRe.FindAllStringSubmatch(doc, -1) {
		if documented[match[1]] {
			t.Errorf("%s documents %q twice", configDocPath, match[1])
		}
		documented[match[1]] = true
	}

	fileRowRe := regexp.MustCompile("(?m)^\\| `([A-Za-z]+)` \\| `([A-Za-z]+File)` \\|$")
	fileVariants := map[string]bool{}
	for _, match := range fileRowRe.FindAllStringSubmatch(doc, -1) {
		if match[1]+"File" != match[2] {
			t.Errorf("%s pairs %q with %q", configDocPath, match[1], match[2])
		}
		fileVariants[match[2]] = true
	}

	known := map[string]bool{}
	for _, key := range configKeys(t) {
		known[key] = true
		if strings.HasSuffix(key, "File") {
			if !fileVariants[key] {
				t.Errorf("%s: %q is missing from the \"Read a value from a file\" table", configDocPath, key)
			}

			continue
		}
		if !documented[key] {
			t.Errorf("%s: setting %q has no \"#### `%s`\" heading", configDocPath, key, key)
		}
	}

	for key := range documented {
		if !known[key] {
			t.Errorf("%s documents %q, which is not a setting of configuration.Config", configDocPath, key)
		}
	}
	for key := range fileVariants {
		if !known[key] {
			t.Errorf("%s lists %q, which is not a setting of configuration.Config", configDocPath, key)
		}
	}
}

// docFiles lists the README and every page under docs/, as slash paths relative to the repository root.
func docFiles(t *testing.T) []string {
	t.Helper()

	files := []string{"README.md"}
	err := filepath.WalkDir(filepath.Join(repoRoot, "docs"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".md" {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))

		return nil
	})
	if err != nil {
		t.Fatalf("walk docs: %v", err)
	}

	return files
}

// stripCode removes fenced code blocks and inline code spans, where brackets and parentheses are not links.
func stripCode(content string) string {
	var out strings.Builder
	inFence := false
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence

			continue
		}
		if inFence {
			continue
		}
		out.WriteString(line)
		out.WriteString("\n")
	}

	return regexp.MustCompile("`+[^`]*`+").ReplaceAllString(out.String(), "")
}

// githubSlug turns a heading into the anchor GitHub gives it.
func githubSlug(heading string) string {
	var slug strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r == ' ':
			slug.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			slug.WriteRune(r)
		}
	}

	return slug.String()
}

// anchors returns every anchor of a Markdown page: one per heading, numbered like GitHub for duplicates,
// plus explicit <a name="..."> anchors.
func anchors(content string) map[string]bool {
	found := map[string]bool{}
	seen := map[string]int{}
	inFence := false
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence

			continue
		}
		if inFence || !strings.HasPrefix(line, "#") {
			continue
		}
		text := strings.TrimSpace(strings.TrimLeft(line, "#"))
		slug := githubSlug(text)
		if count := seen[slug]; count > 0 {
			found[slug+"-"+strconv.Itoa(count)] = true
		} else {
			found[slug] = true
		}
		seen[slug]++
	}

	for _, match := range regexp.MustCompile(`<a name="([^"]+)"></a>`).FindAllStringSubmatch(content, -1) {
		found[match[1]] = true
	}

	return found
}

// resolveLink maps a link found in page to a repository path and an anchor.
// It returns ok false for links outside this repository.
func resolveLink(page, target string) (path, anchor string, ok bool) {
	switch {
	case strings.HasPrefix(target, blobPrefix):
		target = strings.TrimPrefix(target, blobPrefix)
	case strings.HasPrefix(target, rawPrefix):
		target = strings.TrimPrefix(target, rawPrefix)
	case strings.Contains(target, "://"), strings.HasPrefix(target, "mailto:"):
		return "", "", false
	default:
		if !strings.HasPrefix(target, "#") {
			target = filepath.ToSlash(filepath.Join(filepath.Dir(page), target))
		}
	}

	path, anchor, _ = strings.Cut(target, "#")
	if path == "" {
		path = page
	}

	return path, anchor, true
}

// TestDocLinksResolve fails on a link from the README or docs/ to a file or heading that does not exist,
// including absolute links to this repository's master branch.
func TestDocLinksResolve(t *testing.T) {
	linkRe := regexp.MustCompile(`\]\(([^)\s]+)\)|<img src="([^"]+)"`)
	anchorCache := map[string]map[string]bool{}

	for _, page := range docFiles(t) {
		content := stripCode(readDoc(t, page))
		for _, match := range linkRe.FindAllStringSubmatch(content, -1) {
			target := match[1] + match[2]
			path, anchor, ok := resolveLink(page, target)
			if !ok {
				continue
			}

			info, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(path)))
			if err != nil {
				t.Errorf("%s: link %q: %s does not exist", page, target, path)

				continue
			}
			if anchor == "" {
				continue
			}
			if info.IsDir() || filepath.Ext(path) != ".md" {
				t.Errorf("%s: link %q: anchor on a file that is not Markdown", page, target)

				continue
			}

			if anchorCache[path] == nil {
				anchorCache[path] = anchors(readDoc(t, path))
			}
			if !anchorCache[path][anchor] {
				t.Errorf("%s: link %q: %s has no heading #%s", page, target, path, anchor)
			}
		}
	}
}
