package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFetcherFollowsRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
			return
		}
		_, _ = w.Write([]byte("<title>final</title><body>ok</body>"))
	}))
	defer ts.Close()
	f, err := NewFetcher(DefaultOption())
	require.NoError(t, err)
	b, err := f.GetBanner(context.Background(), ts.URL)
	assert.NoError(t, err)
	assert.Equal(t, "final", b.Title)
}

func TestRequestOncePreservesRedirectContextOnLaterFailure(t *testing.T) {
	finalErr := errors.New("headers too large")
	client := retryablehttp.NewClient(retryablehttp.Options{
		RetryMax: 0,
		HttpClient: disableAutoRedirect(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/" {
				return &http.Response{
					StatusCode: http.StatusFound,
					Status:     "302 Found",
					Header:     http.Header{"Location": []string{"/final"}},
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil
			}
			return nil, finalErr
		})}),
	})

	_, _, err := requestOnce(context.Background(), client, "http://example.test/", DefaultOption())
	require.Error(t, err)
	assert.ErrorIs(t, err, finalErr)

	var redirectErr *RedirectError
	require.ErrorAs(t, err, &redirectErr)
	require.Len(t, redirectErr.Hops, 1)
	assert.Equal(t, "http://example.test/", redirectErr.Hops[0].From)
	assert.Equal(t, "http://example.test/final", redirectErr.Hops[0].To)
	assert.Equal(t, http.StatusFound, redirectErr.Hops[0].StatusCode)
	assert.Contains(t, err.Error(), "http://example.test/ [302] -> http://example.test/final")
}

func TestRequestOnceReturnsErrorForMalformedRedirectRequest(t *testing.T) {
	client := retryablehttp.NewClient(retryablehttp.Options{
		RetryMax: 0,
		HttpClient: disableAutoRedirect(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusFound,
				Status:     "302 Found",
				Header:     http.Header{"Location": []string{"http://[fe80::1%25en0]/final"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		})}),
	})

	_, _, err := requestOnce(context.Background(), client, "http://example.test/", DefaultOption())
	require.Error(t, err)

	var redirectErr *RedirectError
	require.ErrorAs(t, err, &redirectErr)
	require.Len(t, redirectErr.Hops, 1)
	assert.Equal(t, "http://example.test/", redirectErr.Hops[0].From)
	assert.Equal(t, "http://[fe80::1%25en0]/final", redirectErr.Hops[0].To)
}

func TestFetcherAllowsLargeResponseHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Large-Header", strings.Repeat("a", 8192))
		_, _ = w.Write([]byte("<title>large header</title><body>ok</body>"))
	}))
	defer ts.Close()

	f, err := NewFetcher(DefaultOption())
	require.NoError(t, err)

	b, err := f.GetBanner(context.Background(), ts.URL)
	require.NoError(t, err)
	assert.Equal(t, "large header", b.Title)
	assert.Contains(t, b.Body, "ok")
}

func TestFetcherOptions(t *testing.T) {
	o := DefaultOption()
	o.MaxBodySize = 16
	o.DisableJavaScript = true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("a", 128))) }))
	defer ts.Close()
	f, err := NewFetcher(o)
	require.NoError(t, err)
	b, err := f.GetBanner(context.Background(), ts.URL)
	assert.NoError(t, err)
	assert.Len(t, b.Body, 16)
}

func TestFetcherFollowsJavaScriptRedirectForSmallBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`<script>window.location.href="/final"</script>`))
			return
		}
		_, _ = w.Write([]byte("<title>js final</title><body>ok</body>"))
	}))
	defer ts.Close()

	f, err := NewFetcher(DefaultOption())
	require.NoError(t, err)

	banners, err := f.GetBanners(context.Background(), ts.URL)
	require.NoError(t, err)
	require.Len(t, banners, 2)
	assert.Equal(t, "js final", banners[1].Title)
}

func TestFetcherSkipsJavaScriptRedirectForLargeBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(strings.Repeat("a", int(DefaultMaxJavaScriptRedirectBodySize)+1)))
			_, _ = w.Write([]byte(`<script>window.location.href="/final"</script>`))
			return
		}
		_, _ = w.Write([]byte("<title>js final</title><body>ok</body>"))
	}))
	defer ts.Close()

	f, err := NewFetcher(DefaultOption())
	require.NoError(t, err)

	banners, err := f.GetBanners(context.Background(), ts.URL)
	require.NoError(t, err)
	require.Len(t, banners, 1)
	assert.NotEqual(t, "js final", banners[0].Title)
}

func TestFetcherHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f, err := NewFetcher(DefaultOption())
	require.NoError(t, err)
	_, err = f.GetBanner(ctx, "http://127.0.0.1:1")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
}

func TestFetcherUsesRequestTimeoutWithParentDeadline(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(100 * time.Millisecond) }))
	defer ts.Close()
	o := DefaultOption()
	o.Timeout = 20 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, err := NewFetcher(o)
	require.NoError(t, err)
	_, err = f.GetBanner(ctx, ts.URL)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestReadIconClosesNonOKResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`<html><link rel="icon" href="/favicon.ico"></html>`))
	}))
	defer ts.Close()
	f, err := NewFetcher(DefaultOption())
	require.NoError(t, err)
	b, err := f.GetBanner(context.Background(), ts.URL)
	assert.NoError(t, err)
	assert.Zero(t, b.IconHash)
}
