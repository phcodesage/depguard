// Package advisory queries known vulnerabilities. It does not execute package code.
package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/phcodesage/depguard/internal/model"
)

const Endpoint = "https://api.osv.dev/v1/querybatch"

type Client struct {
	HTTP     *http.Client
	Endpoint string
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, Endpoint: Endpoint}
}

type query struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type result struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

// Scan queries each distinct ecosystem/name/version once and maps results to all locations.
// Errors preserve already retrieved findings and must be reported as incomplete coverage.
func (c *Client) Scan(ctx context.Context, dependencies []model.Dependency) ([]model.Finding, error) {
	findings := []model.Finding{}
	queries := []query{}
	locations := map[string][]model.Dependency{}
	key := func(ecosystem, name, version string) string { return ecosystem + "\x00" + name + "\x00" + version }
	for _, dep := range dependencies {
		k := key(dep.Ecosystem, dep.Name, dep.Version)
		if _, exists := locations[k]; !exists {
			q := query{Version: dep.Version}
			q.Package.Name = dep.Name
			q.Package.Ecosystem = dep.Ecosystem
			queries = append(queries, q)
		}
		locations[k] = append(locations[k], dep)
	}
	seen := map[string]bool{}
	for start := 0; start < len(queries); start += 100 {
		end := min(start+100, len(queries))
		pending := append([]query(nil), queries[start:end]...)
		for page := 0; len(pending) > 0; page++ {
			if page >= 100 {
				return findings, fmt.Errorf("OSV pagination limit reached; advisory coverage is incomplete")
			}
			results, err := c.batch(ctx, pending)
			if err != nil {
				return findings, err
			}
			next := []query{}
			for i, item := range results {
				q := pending[i]
				for _, v := range item.Vulns {
					if strings.TrimSpace(v.ID) == "" {
						return findings, fmt.Errorf("OSV returned an empty advisory ID")
					}
					for _, dep := range locations[key(q.Package.Ecosystem, q.Package.Name, q.Version)] {
						k := dep.Lockfile + "\x00" + dep.Location + "\x00" + v.ID
						if seen[k] {
							continue
						}
						seen[k] = true
						findings = append(findings, model.Finding{Dependency: dep, ID: v.ID, URL: "https://osv.dev/vulnerability/" + url.PathEscape(v.ID)})
					}
				}
				if item.NextPageToken != "" {
					if item.NextPageToken == q.PageToken {
						return findings, fmt.Errorf("OSV repeated its pagination token")
					}
					q.PageToken = item.NextPageToken
					next = append(next, q)
				}
			}
			pending = next
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		return a.Dependency.Lockfile+"\x00"+a.Dependency.Location+"\x00"+a.ID < b.Dependency.Lockfile+"\x00"+b.Dependency.Location+"\x00"+b.ID
	})
	return findings, nil
}

func (c *Client) batch(ctx context.Context, queries []query) ([]result, error) {
	body, err := json.Marshal(struct {
		Queries []query `json:"queries"`
	}{queries})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cannot construct OSV request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "depguard/0.1.0-dev")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV request failed; advisory coverage is incomplete")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned HTTP %d; advisory coverage is incomplete", resp.StatusCode)
	}
	const limit = 32 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(data) > limit {
		return nil, fmt.Errorf("cannot read bounded OSV response")
	}
	var response struct {
		Results []*result `json:"results"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("OSV returned invalid JSON")
	}
	if len(response.Results) != len(queries) {
		return nil, fmt.Errorf("OSV result count mismatch; advisory coverage is incomplete")
	}
	results := make([]result, len(response.Results))
	for i, item := range response.Results {
		if item == nil {
			return nil, fmt.Errorf("OSV returned a null result; advisory coverage is incomplete")
		}
		results[i] = *item
	}
	return results, nil
}
