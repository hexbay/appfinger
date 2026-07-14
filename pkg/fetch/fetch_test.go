package fetch

import (
	"context"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

	banner, redirectURL, err := RequestOnce(NewFetcher(DefaultOption()).GetClient(), ts.URL)
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
	banner, redirectURL, err := RequestOnce(NewFetcher(options).GetClient(), ts.URL, options)
	assert.NoError(t, err)
	assert.NotNil(t, banner)
	assert.Empty(t, redirectURL)
}

func TestRequestOnceLimitsBodySize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 128)))
	}))
	defer ts.Close()

	options := DefaultOption()
	options.MaxBodySize = 16
	options.DisableJavaScript = true
	banner, _, err := RequestOnce(NewFetcher(options).GetClient(), ts.URL, options)

	assert.NoError(t, err)
	assert.Len(t, banner.Body, 16)
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
