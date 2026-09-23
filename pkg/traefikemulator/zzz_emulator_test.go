package traefikemulator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type recorded struct {
	body string
}

func (r *recorded) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(r.body))
}

func TestApply_CancelsPreviousGenerationBeforeNextNew(t *testing.T) {
	var seen []context.Context
	generation := New(func(ctx context.Context, next http.Handler, _ any, middlewareName string) (http.Handler, error) {
		if middlewareName == "second" && seen[0].Err() == nil {
			t.Fatal("previous generation still live when the next New runs")
		}
		seen = append(seen, ctx)
		return next, nil
	})
	t.Cleanup(generation.Stop)

	if failed := generation.Apply([]Route{{Name: "first", Next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}}); failed != nil {
		t.Fatal(failed)
	}
	if failed := generation.Apply([]Route{{Name: "second", Next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}}); failed != nil {
		t.Fatal(failed)
	}
}

func TestApply_RoutesShareOneContext(t *testing.T) {
	var contexts []context.Context
	generation := New(func(ctx context.Context, next http.Handler, _ any, _ string) (http.Handler, error) {
		contexts = append(contexts, ctx)
		return next, nil
	})
	t.Cleanup(generation.Stop)

	if failed := generation.Apply([]Route{{Name: "a"}, {Name: "b"}}); failed != nil {
		t.Fatal(failed)
	}
	if len(contexts) != 2 || contexts[0] != contexts[1] {
		t.Fatalf("contexts %d, shared %v", len(contexts), len(contexts) == 2 && contexts[0] == contexts[1])
	}
	generation.Stop()
	if contexts[0].Err() == nil || contexts[1].Err() == nil {
		t.Fatal("one generation cancel must end every route context")
	}
}

func TestApply_OmittedRouteIsNotConstructed(t *testing.T) {
	var names []string
	generation := New(func(_ context.Context, next http.Handler, _ any, middlewareName string) (http.Handler, error) {
		names = append(names, middlewareName)
		return next, nil
	})
	t.Cleanup(generation.Stop)

	if failed := generation.Apply([]Route{{Name: "a"}, {Name: "b"}}); failed != nil {
		t.Fatal(failed)
	}
	if failed := generation.Apply([]Route{{Name: "b"}}); failed != nil {
		t.Fatal(failed)
	}
	if len(names) != 3 || names[0] != "a" || names[1] != "b" || names[2] != "b" {
		t.Fatalf("constructed %v", names)
	}
}

func TestApply_FailedNewIsAbsentAndSiblingStays(t *testing.T) {
	var seen []context.Context
	generation := New(func(ctx context.Context, next http.Handler, _ any, middlewareName string) (http.Handler, error) {
		if middlewareName == "bad" {
			return nil, errors.New("rejected")
		}
		seen = append(seen, ctx)
		return next, nil
	})
	t.Cleanup(generation.Stop)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	failed := generation.Apply([]Route{{Name: "good", Next: next}, {Name: "bad"}})
	if failed["bad"] == nil {
		t.Fatal("bad route must fail New")
	}
	if _, ok := generation.Handler("bad"); ok {
		t.Fatal("failed New must be absent")
	}
	if seen[0].Err() != nil {
		t.Fatal("a failed New must not cancel the generation")
	}
	recorder := httptest.NewRecorder()
	if !generation.Serve("good", recorder, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("sibling must still serve")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("sibling status %d", recorder.Code)
	}
}

func TestServe_HitsCurrentGenerationOnly(t *testing.T) {
	generation := New(func(_ context.Context, next http.Handler, _ any, _ string) (http.Handler, error) {
		return next, nil
	})
	t.Cleanup(generation.Stop)

	if failed := generation.Apply([]Route{{Name: "r", Next: &recorded{body: "old"}}}); failed != nil {
		t.Fatal(failed)
	}
	if failed := generation.Apply([]Route{{Name: "r", Next: &recorded{body: "new"}}}); failed != nil {
		t.Fatal(failed)
	}
	recorder := httptest.NewRecorder()
	if !generation.Serve("r", recorder, httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("current route missing")
	}
	if recorder.Body.String() != "new" {
		t.Fatalf("body %q", recorder.Body.String())
	}
}

func TestApply_SharedMiddlewareNameConstructsTwice(t *testing.T) {
	var contexts []context.Context
	var calls int
	generation := New(func(ctx context.Context, next http.Handler, _ any, middlewareName string) (http.Handler, error) {
		if middlewareName != "shared" {
			t.Fatalf("middleware name %q", middlewareName)
		}
		calls++
		contexts = append(contexts, ctx)
		return next, nil
	})
	t.Cleanup(generation.Stop)

	routes := []Route{
		{Name: "left", MiddlewareName: "shared"},
		{Name: "right", MiddlewareName: "shared"},
	}
	if failed := generation.Apply(routes); failed != nil {
		t.Fatal(failed)
	}
	if calls != 2 {
		t.Fatalf("New calls %d", calls)
	}
	generation.Stop()
	if contexts[0].Err() == nil || contexts[1].Err() == nil {
		t.Fatal("one generation cancel must end both holders of the shared middleware name")
	}
}
