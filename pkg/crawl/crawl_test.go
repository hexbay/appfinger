package crawl

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

func TestCrawl(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	crawl := NewCrawler(DefaultOption())
	banner, err := crawl.GetBanner(context.Background(), "https://www.hackerone.com")
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

	banner, redirectURL, err := RequestOnce(NewCrawler(DefaultOption()).GetClient(), ts.URL)
	assert.NoError(t, err)
	assert.Empty(t, redirectURL)
	assert.NotNil(t, banner)
	assert.True(t, strings.HasSuffix(banner.Uri, "/final"))
	assert.Equal(t, http.StatusOK, banner.StatusCode)
}
