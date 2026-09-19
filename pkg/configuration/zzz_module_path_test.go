package configuration

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// forkModulePath is this tree's Go and Traefik module identity after the retarget.
const forkModulePath = "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin"

// forkModuleRoot walks from this test file to the directory that holds go.mod.
func forkModuleRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above this test")
		}
		dir = parent
	}
}

// TestForkModulePathMatchesManifest fails if go.mod or .traefik.yml is reverted
// to a path other than this fork (DestBranch still named maxlerebourg).
// Lives under pkg/ so `yaegi test .` at the plugin root does not interpret it.
func TestForkModulePathMatchesManifest(t *testing.T) {
	root := forkModuleRoot(t)

	goMod, err := os.ReadFile(filepath.Join(root, "go.mod")) //nolint:gosec // module-root fixture
	if err != nil {
		t.Fatal(err)
	}
	goModText := strings.ReplaceAll(string(goMod), "\r\n", "\n")
	if !strings.HasPrefix(goModText, "module "+forkModulePath+"\n") {
		t.Fatalf("go.mod module line does not name %s", forkModulePath)
	}

	manifest, err := os.ReadFile(filepath.Join(root, ".traefik.yml")) //nolint:gosec // module-root fixture
	if err != nil {
		t.Fatal(err)
	}
	manifestText := string(manifest)
	if !strings.Contains(manifestText, "import: "+forkModulePath) {
		t.Fatalf(".traefik.yml import does not name %s", forkModulePath)
	}
	if !strings.Contains(manifestText, "displayName: CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)") {
		t.Fatal(".traefik.yml displayName is not the fork string")
	}
}
