package fetch

import (
	"context"
	"errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetch(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	fetcher := NewFetcher(DefaultOption())
	banner, err := fetcher.GetBanner(context.Background(), "https://www.hackerone.com")
	assert.NoError(t, err)
	assert.NotNil(t, banner)
	assert.Equal(t, banner.StatusCode, 200)
}

func TestRequestOnceFollowsTemporaryRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
		case "/final":
			_, _ = w.Write([]byte("<html><title>final</title><body>ok</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	banner, redirectURL, err := RequestOnce(context.Background(), NewFetcher(DefaultOption()).GetClient(), ts.URL)
	assert.NoError(t, err)
	assert.Empty(t, redirectURL)
	assert.NotNil(t, banner)
	assert.True(t, strings.HasSuffix(banner.Uri, "/final"))
	assert.Equal(t, http.StatusOK, banner.StatusCode)
}

func TestRequestOnceCanDisableJavaScriptRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><script>window.location.href="/next";</script></html>`))
	}))
	defer ts.Close()

	options := DefaultOption()
	options.DisableJavaScript = true
	banner, redirectURL, err := RequestOnce(context.Background(), NewFetcher(options).GetClient(), ts.URL, options)
	assert.NoError(t, err)
	assert.NotNil(t, banner)
	assert.Empty(t, redirectURL)
}

func TestRequestOnceSkipsJavaScriptParsingForPlainHTML(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><title>plain</title><body>hello</body></html>`))
	}))
	defer ts.Close()

	banner, redirectURL, err := RequestOnce(context.Background(), NewFetcher(DefaultOption()).GetClient(), ts.URL)
	assert.NoError(t, err)
	assert.NotNil(t, banner)
	assert.Empty(t, redirectURL)
	assert.Equal(t, "plain", banner.Title)
}

func TestRequestOnceLimitsBodySize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 128)))
	}))
	defer ts.Close()

	options := DefaultOption()
	options.MaxBodySize = 16
	options.DisableJavaScript = true
	banner, _, err := RequestOnce(context.Background(), NewFetcher(options).GetClient(), ts.URL, options)

	assert.NoError(t, err)
	assert.Len(t, banner.Body, 16)
}

func TestRequestOnceHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := RequestOnce(ctx, NewFetcher(DefaultOption()).GetClient(), "http://127.0.0.1:1")

	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "expected context canceled, got %v", err)
}

func TestFetcherDialUsesRequestContext(t *testing.T) {
	options := DefaultOption()
	options.Timeout = 150 * time.Millisecond
	fetcher := NewFetcher(options)

	transport, ok := fetcher.GetClient().HTTPClient.Transport.(*http.Transport)
	assert.True(t, ok)
	assert.NotNil(t, transport.DialContext)
}

func TestRequestOnceExternalDeadlineOverridesOptionsTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	options := DefaultOption()
	options.Timeout = time.Nanosecond
	options.DisableJavaScript = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	banner, _, err := RequestOnce(ctx, NewFetcher(options).GetClient(), ts.URL, options)

	assert.NoError(t, err)
	assert.Equal(t, "ok", banner.Body)
}

func TestReadIconClosesNonOKResponse(t *testing.T) {
	var iconRequested bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><link rel="icon" href="/favicon.ico"></html>`))
		case "/favicon.ico":
			iconRequested = true
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
		}
	}))
	defer ts.Close()

	fetcher := NewFetcher(DefaultOption())
	banner, err := fetcher.GetBanner(context.Background(), ts.URL)

	assert.NoError(t, err)
	assert.NotNil(t, banner)
	assert.True(t, iconRequested)
	assert.Zero(t, banner.IconHash)
}
