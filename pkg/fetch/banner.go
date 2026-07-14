package fetch

import (
	"crypto/tls"
	"strings"
)

// Banner 表示爬取的网站信息
type Banner struct {
	Uri         string               `json:"uri"`
	BodyHash    int32                `json:"body_hash"`
	Body        string               `json:"body"`
	Header      string               `json:"header"`
	Headers     map[string]string    `json:"-"`
	Title       string               `json:"title"`
	StatusCode  int                  `json:"status_code"`
	Response    string               `json:"_"`
	SSL         bool                 `json:"ssl"`
	Certificate string               `json:"certificate"`
	IconHash    int32                `json:"icon_hash"`
	IconType    string               `json:"icon_type"`
	Charset     string               `json:"-"`
	Cert        *tls.ConnectionState `json:"-"`
	IconURI     string               `json:"icon_uri"`
	IconBytes   []byte               `json:"-"`
	Compliance  map[string]string    `json:"-"`
}

// 缓存小写内容、避免匹配时进行大小写转换出现的性能损耗、虽然会增加内存开销、但是可以显著提高匹配速度
func (b *Banner) CacheLower() {
	for k, v := range b.Headers {
		b.Compliance[strings.ToLower(k)] = v
	}
}
