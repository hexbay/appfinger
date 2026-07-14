package wordpress

import "testing"

func TestMatchPlugins(t *testing.T) {
	body := `
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2.3">
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.9.8"></script>
`

	result := MatchPlugins(body)

	plugin := result["contact-form-7"]
	if plugin["framework"] != "wordpress" || plugin["type"] != "plugins" || plugin["version"] != "5.9.8" {
		t.Fatalf("unexpected plugin result: %#v", plugin)
	}

	theme := result["twentytwentyfour"]
	if theme["framework"] != "wordpress" || theme["type"] != "themes" || theme["version"] != "1.2.3" {
		t.Fatalf("unexpected theme result: %#v", theme)
	}
}
