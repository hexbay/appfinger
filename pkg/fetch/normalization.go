package fetch

import (
	"compress/gzip"
	"compress/zlib"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"net/http"
	"strings"
)

// wrapDecodeReader wraps a decompression reader around the response body if it's compressed
// using gzip or deflate.
func wrapDecodeReader(resp *http.Response) (rc io.ReadCloser, err error) {
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		rc, err = gzip.NewReader(resp.Body)
	case "deflate":
		rc, err = zlib.NewReader(resp.Body)
	default:
		rc = resp.Body
	}
	if err != nil {
		return nil, err
	}
	// handle GBK encoding
	if isContentTypeGbk(resp.Header.Get("Content-Type")) {
		rc = io.NopCloser(transform.NewReader(rc, simplifiedchinese.GBK.NewDecoder()))
	}
	return rc, nil
}

// isContentTypeGbk checks if the content-type header is gbk
func isContentTypeGbk(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return stringsutil.ContainsAny(contentType, "gbk", "gb2312", "gb18030")
}
