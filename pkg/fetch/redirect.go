package fetch

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/robertkrimen/otto"
	"golang.org/x/net/html"
	"net/url"
	"strings"
	"time"
)

const JSExecuteTemplate = `
		var navigator = {language:"en",
						appVersion:"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
						appCodeName: "Mozilla",
						appName:"Netscape",
						userAgent:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
						vendor:"Google Inc.",
						};
		var location = {href:"%s",hostname:"%s","protocol":"%s",pathname:"%s",search:""};
		var window = {
			location: location,
			open: function(url, target) {
				window.location.href =url;
			}
		};
		var top = {
			window: window,
			location: location,
			document: {
				location: window.location		
			}
		}
		var document = {
			location: window.location,	
		};
		window.top = top;
		self = window;
`

func extractUri(n *html.Node) string {
	// 处理 <meta http-equiv="Refresh" content="0;url=/yyoa/index.jsp"> 标签
	for _, attr := range n.Attr {
		if attr.Key == "content" {
			parts := strings.Split(attr.Val, ";")
			for _, part := range parts {
				if strings.Contains(strings.ToLower(part), "url=") {
					redirectURL := strings.TrimSpace(strings.SplitN(part, "=", 2)[1])
					if strings.HasSuffix(redirectURL, "'") && strings.HasPrefix(redirectURL, "'") {
						redirectURL = redirectURL[1 : len(redirectURL)-1]
					}
					return redirectURL
				}
			}
		}
	}
	return ""
}

func findRefresh(n *html.Node) string {
	var uri string
	if n.Type == html.ElementNode && n.Data == "meta" {
		for _, attr := range n.Attr {
			if strings.ToLower(attr.Key) == "http-equiv" && strings.ToLower(attr.Val) == "refresh" {
				uri = extractUri(n)
				if uri != "" {
					return uri

				}
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		uri = findRefresh(c)
		if uri != "" {
			return uri
		}
	}
	return ""
}
func getExecRedirect(uri string, jsCodes []string, onload string) string {
	vm := otto.New()
	parsed, _ := url.Parse(url.PathEscape(uri))
	var scripts []string
	initWindowsCode := fmt.Sprintf(JSExecuteTemplate, uri, parsed.Hostname(), parsed.Scheme, parsed.Path)
	scripts = append(scripts, initWindowsCode)
	var consoleLogs []string
	_ = vm.Set("console", map[string]interface{}{
		"log": func(call otto.FunctionCall) otto.Value {
			for _, arg := range call.ArgumentList {
				value, _ := arg.Export()
				consoleLogs = append(consoleLogs, fmt.Sprint(value))
			}
			return otto.Value{}
		},
	})
	for _, code := range jsCodes {
		scripts = append(scripts, code)
	}
	code := fmt.Sprintf(`
		%s
		function isString(s) {
			return typeof(s) ==="string";
		}
		if (window.onload) {
			window.onload();
		}
		if(self.location){
			if(isString(self.location)){
				window.location.href = self.location;
			}else{
				window.location.href = self.location.href;
			}
		}
		if(location.href){
			window.location.href = location.href;
		}
		if(top.document.location.href){
			window.location.href = top.document.location.href;
		}
		var finalHref;
		if (Object.prototype.toString.call(window.location)=== '[object Object]') {
			finalHref = window.location.href;
		}else{
			finalHref = window.location;
		}
	`, onload)
	scripts = append(scripts, code)
	for _, script := range scripts {
		err := runScriptWithTimeout(vm, script, 2*time.Second)
		if err != nil {
			gologger.Debug().Msgf("Error running script:%v", err)
			return ""
		}
	}
	// 获取执行后的地址
	result, err := vm.Get("finalHref")
	if err != nil {
		gologger.Debug().Msgf("Error getting result:%v", err)
		return ""
	}
	r2 := result.String()
	if r2 == uri {
		return ""
	}
	return result.String()
}
func findAttribute(attrs []html.Attribute, key string) string {
	for _, attr := range attrs {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}
func ExtractCharset(htmlContent string) string {
	reader := strings.NewReader(htmlContent)
	doc, err := html.Parse(reader)
	if err != nil {
		return "UTF-8"
	}

	var charset string
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "meta" {
			for _, attr := range n.Attr {
				if attr.Key == "http-equiv" && strings.EqualFold(attr.Val, "Content-Type") {
					contentAttr := findAttribute(n.Attr, "content")
					charsetIndex := strings.Index(contentAttr, "charset=")
					if charsetIndex != -1 {
						charset = contentAttr[charsetIndex+len("charset="):]
						return
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)
	return strings.ToUpper(strings.TrimSpace(charset))
}

func parseJavaScript(url string, htmlContent string) string {
	// 在这里解析JavaScript，提取跳转信息
	//<meta http-equiv="Refresh"content="0;url=/yyoa/index.jsp">
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return ""
	}
	var uri string
	for c := doc.FirstChild; c != nil; c = c.NextSibling {
		uri = findRefresh(c)
		if uri != "" {
			return uri
		}
	}
	var visitNode func(n *html.Node)
	var scripts []string
	var onload string
	visitNode = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "body" {
			for _, attr := range n.Attr {
				if attr.Key == "onload" {
					onload = attr.Val
				}
			}
		}
		// 如果节点是一个script标签并且包含JavaScript代码，则将其添加到切片中
		if n.Type == html.ElementNode && n.Data == "script" {
			var jsCode string
			// 提取script标签内的文本内容
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.TextNode {
					jsCode += c.Data
				}
			}
			// 将JavaScript代码添加到切片中
			if jsCode != "" {
				scripts = append(scripts, jsCode)
			}
		}
		// 递归遍历子节点
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visitNode(c)
		}
	}
	visitNode(doc)
	if len(scripts) > 2 {
		return ""
	} else {
		// parse onload
		if strings.HasPrefix(onload, "javascript:") {
			return getExecRedirect(url, scripts, strings.Split(onload, ":")[1])
		} else {
			return getExecRedirect(url, scripts, onload)
		}
	}
}

func urlJoin(base, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if strings.HasPrefix(path, "../") {
		//	 todo last path
		path = strings.TrimPrefix(path, "..")
	}
	if base[len(base)-1] != '/' && path[0] != '/' {
		base += "/"
	}
	if base[len(base)-1] == '/' && path[0] == '/' {
		path = path[1:]
	}
	return base + path
}
func joinURL(baseURL, path string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	var ref = &url.URL{}
	if strings.Contains(path, "?") {
		ref.Path = strings.Split(path, "?")[0]
		ref.RawQuery = strings.Split(path, "?")[1]
	} else {
		ref.Path = strings.Split(path, "?")[0]
	}
	// 使用 ResolveReference 方法拼接路径
	fullURL := base.ResolveReference(ref)
	return fullURL.String()
}
