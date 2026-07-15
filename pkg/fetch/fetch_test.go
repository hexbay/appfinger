package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFetcherFollowsRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
			return
		}
		_, _ = w.Write([]byte("<title>final</title><body>ok</body>"))
	}))
	defer ts.Close()
	b, err := NewFetcher(DefaultOption()).GetBanner(context.Background(), ts.URL)
	assert.NoError(t, err)
	assert.Equal(t, "final", b.Title)
}

func TestFetcherOptions(t *testing.T) {
	o := DefaultOption()
	o.MaxBodySize = 16
	o.DisableJavaScript = true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("a", 128))) }))
	defer ts.Close()
	b, err := NewFetcher(o).GetBanner(context.Background(), ts.URL)
	assert.NoError(t, err)
	assert.Len(t, b.Body, 16)
}

func TestFetcherHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewFetcher(DefaultOption()).GetBanner(ctx, "http://127.0.0.1:1")
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
	_, err := NewFetcher(o).GetBanner(ctx, ts.URL)
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
	b, err := NewFetcher(DefaultOption()).GetBanner(context.Background(), ts.URL)
	assert.NoError(t, err)
	assert.Zero(t, b.IconHash)
}
