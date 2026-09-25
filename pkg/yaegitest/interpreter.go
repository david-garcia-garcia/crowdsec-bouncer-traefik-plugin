// Package yaegitest builds a Yaegi v0.16.1 interpreter that loads this module
// the way Traefik does: GOPATH/src plus the vendored middleware utilities.
package yaegitest

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

// ModulePath is this plugin's Go module path.
const ModulePath = "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin"

const utilitiesModulePath = "github.com/david-garcia-garcia/traefik-middleware-utilities"

// Interpreter is one Yaegi v0.16.1 session whose imports resolve from a GoPath.
type Interpreter struct {
	session *interp.Interpreter
}

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

// New starts an interpreter that loads source from goPath.
// goPath comes from GoPath. Each New is its own session.
func New(t *testing.T, goPath string) *Interpreter {
	t.Helper()
	session := interp.New(interp.Options{
		GoPath: goPath,
		Env:    os.Environ(),
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err := session.Use(stdlib.Symbols); err != nil {
		t.Fatal(err)
	}
	return &Interpreter{session: session}
}

// Eval evaluates source in this session.
func (i *Interpreter) Eval(source string) (reflect.Value, error) {
	return i.session.Eval(source)
}

// EvalError evaluates an expression that returns error and returns that error.
// A panic during the expression is returned as the error. A nil error is success.
func (i *Interpreter) EvalError(expression string) error {
	result, err := i.session.Eval(expression)
	if err != nil {
		return err
	}
	return errorResult(result)
}

// errorResult is the error value an interpreted call returned. A nil interface is success.
func errorResult(result reflect.Value) error {
	if !result.IsValid() || result.IsNil() {
		return nil
	}
	returned, ok := result.Interface().(error)
	if !ok || returned == nil {
		return nil
	}
	return returned
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
