// Package yaegitest runs a program under the yaegi v0.16.1 binary the way Traefik
// loads this module: GOPATH/src plus the vendored middleware utilities.
// The binary is not a module dependency. CI installs it before the test suite.
package yaegitest

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// ModulePath is this plugin's Go module path.
const ModulePath = "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin"

const utilitiesModulePath = "github.com/david-garcia-garcia/traefik-middleware-utilities"

// GoPath is a GOPATH whose src tree is this module plus vendored utilities.
// Yaegi v0.16 resolves imports from GOPATH/src, the same way Traefik loads the plugin.
func GoPath(t *testing.T) string {
	t.Helper()
	root := moduleRoot(t)
	goPath := t.TempDir()
	linkTree(t, filepath.Join(goPath, "src", ModulePath), root)
	linkTree(t, filepath.Join(goPath, "src", utilitiesModulePath),
		filepath.Join(root, "vendor", utilitiesModulePath))
	return goPath
}

// Run executes source with the yaegi binary. source is a package main program.
// The test skips when the binary is not on PATH. A non-zero exit fails the test.
func Run(t *testing.T, goPath, source string) {
	t.Helper()
	if _, err := exec.LookPath("yaegi"); err != nil {
		t.Skip("yaegi binary not on PATH")
	}
	file := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("yaegi", file) //nolint:gosec // G204 executable is the fixed name yaegi; file is a temp program this test wrote.
	cmd.Env = append(os.Environ(), "GOPATH="+goPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("yaegi: %v\n%s", err, out)
	}
}

// moduleRoot is the directory that contains this module's go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found from the test working directory")
		}
		dir = parent
	}
}

// linkTree exposes target at linkPath so Yaegi can import it. A directory symlink is enough
// on Unix. Windows falls back to a junction when symlink creation is not permitted.
func linkTree(t *testing.T, linkPath, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o750); err != nil {
		t.Fatal(err)
	}
	symlinkErr := os.Symlink(target, linkPath)
	if symlinkErr == nil {
		info, statErr := os.Stat(linkPath)
		if statErr == nil && info.IsDir() {
			return
		}
		_ = os.Remove(linkPath)
	}
	if runtime.GOOS != "windows" {
		t.Fatalf("symlink %s -> %s: %v", linkPath, target, symlinkErr)
	}
	command := exec.Command("cmd", "/c", "mklink", "/J", linkPath, target)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("symlink %s -> %s: %v; junction: %v: %s", linkPath, target, symlinkErr, err, output)
	}
}
