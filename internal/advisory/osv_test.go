package advisory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/phcodesage/depguard/internal/model"
)

func dependency(name, location string) model.Dependency {
	return model.Dependency{Ecosystem: "npm", Name: name, Version: "1.0.0", Lockfile: "package-lock.json", Location: location}
}

func TestDeduplicationPaginationAndLocations(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("invalid request")
		}
		var body struct {
			Queries []query `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if calls == 1 {
			if len(body.Queries) != 2 {
				t.Errorf("expected 2 distinct identities, got %d", len(body.Queries))
			}
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-example"}],"next_page_token":"page2"},{}]}`))
		} else {
			if len(body.Queries) != 1 || body.Queries[0].PageToken != "page2" || body.Queries[0].Package.Name != "a" {
				t.Error("incorrect pagination mapping")
			}
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-example"},{"id":"MAL-example"}]}]}`))
		}
	}))
	defer server.Close()
	c := &Client{HTTP: server.Client(), Endpoint: server.URL}
	findings, err := c.Scan(context.Background(), []model.Dependency{dependency("a", "node_modules/a"), dependency("a", "node_modules/x/node_modules/a"), dependency("b", "node_modules/b")})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(findings) != 4 {
		t.Fatalf("calls=%d, findings=%+v", calls, findings)
	}
}

func TestFailureNeverLooksClean(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"rate limited", 429, `{}`},
		{"server error", 503, `{}`},
		{"bad JSON", 200, `broken`},
		{"wrong result count", 200, `{"results":[]}`},
		{"null result", 200, `{"results":[null]}`},
		{"missing advisory ID", 200, `{"results":[{"vulns":[{}]}]}`},
		{"repeated page token", 200, `{"results":[{"next_page_token":"again"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			c := &Client{HTTP: server.Client(), Endpoint: server.URL}
			if _, err := c.Scan(context.Background(), []model.Dependency{dependency("a", "node_modules/a")}); err == nil {
				t.Fatal("accepted an incomplete response")
			}
		})
	}
}

func TestPartialFindingsPreserved(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-known"}],"next_page_token":"next"}]}`))
			return
		}
		w.WriteHeader(503)
	}))
	defer server.Close()
	c := &Client{HTTP: server.Client(), Endpoint: server.URL}
	findings, err := c.Scan(context.Background(), []model.Dependency{dependency("a", "node_modules/a")})
	if err == nil || len(findings) != 1 {
		t.Fatalf("lost partial result: findings=%v err=%v", findings, err)
	}
}

func TestCancellationAndEmptyInventory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected network request") }))
	defer server.Close()
	c := &Client{HTTP: server.Client(), Endpoint: server.URL}
	if findings, err := c.Scan(context.Background(), nil); err != nil || len(findings) != 0 {
		t.Fatalf("empty inventory: %v %v", findings, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Scan(ctx, []model.Dependency{dependency("a", "node_modules/a")}); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestBatchBoundary(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var request struct {
			Queries []query `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if len(request.Queries) > 100 {
			t.Error("oversized batch")
		}
		response := struct {
			Results []result `json:"results"`
		}{make([]result, len(request.Queries))}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	deps := []model.Dependency{}
	for i := 0; i < 101; i++ {
		deps = append(deps, dependency(string(rune('a'+i)), string(rune('a'+i))))
	}
	c := &Client{HTTP: server.Client(), Endpoint: server.URL}
	if _, err := c.Scan(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 batches, got %d", calls)
	}
}
