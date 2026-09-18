package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// forkModulePath is this tree's Go and Traefik module identity after the retarget.
const forkModulePath = "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin"

// forkModuleRoot is the directory that holds go.mod and .traefik.yml (this test file's dir).
func forkModuleRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return filepath.Dir(thisFile)
}

// TestForkModulePathMatchesManifest fails if go.mod or .traefik.yml is reverted
// to a path other than this fork (DestBranch still named maxlerebourg).
func TestForkModulePathMatchesManifest(t *testing.T) {
	root := forkModuleRoot(t)

	goMod, err := os.ReadFile(filepath.Join(root, "go.mod")) //nolint:gosec // module-root fixture
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(goMod), "module "+forkModulePath+"\n") {
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
