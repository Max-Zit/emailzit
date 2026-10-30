package webmail

import (
	"html"
	"strings"

	xhtml "golang.org/x/net/html"
)

// HTML mail is shown in a sandboxed frame (no scripts, no forms, its own
// opaque origin) and the panel's Content-Security-Policy keeps remote
// images and styles out. On top of that the HTML is reduced to an
// allow-list of tags and attributes here, so nothing active reaches the
// browser even if one of those layers failed.

var allowedTags = map[string]bool{
	"a": true, "abbr": true, "b": true, "blockquote": true, "br": true, "caption": true, "center": true, "code": true,
	"col": true, "colgroup": true, "dd": true, "del": true, "div": true, "dl": true, "dt": true, "em": true, "font": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "hr": true, "i": true, "img": true, "ins": true,
	"li": true, "ol": true, "p": true, "pre": true, "q": true, "s": true, "small": true, "span": true, "strike": true,
	"strong": true, "sub": true, "sup": true, "table": true, "tbody": true, "td": true, "tfoot": true, "th": true,
	"thead": true, "tr": true, "tt": true, "u": true, "ul": true,
}

// content of these tags is dropped entirely
var droppedTags = map[string]bool{"script": true, "style": true, "head": true, "title": true, "iframe": true, "object": true,
	"embed": true, "applet": true, "form": true, "textarea": true, "select": true, "button": true, "noscript": true, "svg": true, "math": true, "template": true}

var allowedAttrs = map[string]bool{"href": true, "src": true, "alt": true, "title": true, "colspan": true, "rowspan": true,
	"width": true, "height": true, "align": true, "valign": true, "border": true, "cellpadding": true, "cellspacing": true, "dir": true, "lang": true}

// SafeHTML reduces mail HTML to harmless markup. Links open in a new
// window; images are kept only when they come with the message (cid:,
// replaced by the caller) or as data: images.
func SafeHTML(in string) string {
	z := xhtml.NewTokenizer(strings.NewReader(in))
	var b strings.Builder
	drop := 0
	for {
		tt := z.Next()
		switch tt {
		case xhtml.ErrorToken:
			return b.String()
		case xhtml.TextToken:
			if drop == 0 {
				b.WriteString(html.EscapeString(string(z.Text())))
			}
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			t := z.Token()
			name := strings.ToLower(t.Data)
			if droppedTags[name] {
				if tt == xhtml.StartTagToken {
					drop++
				}
				continue
			}
			if drop > 0 || !allowedTags[name] {
				continue
			}
			b.WriteString("<" + name)
			for _, a := range t.Attr {
				k := strings.ToLower(a.Key)
				if !allowedAttrs[k] {
					continue
				}
				v := strings.TrimSpace(a.Val)
				lv := strings.ToLower(v)
				switch k {
				case "href":
					if !(strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://") || strings.HasPrefix(lv, "mailto:")) {
						continue
					}
				case "src":
					if !(strings.HasPrefix(lv, "data:image/") || strings.HasPrefix(lv, "cid:")) {
						continue
					}
				}
				b.WriteString(" " + k + `="` + html.EscapeString(v) + `"`)
			}
			if name == "a" {
				b.WriteString(` target="_blank" rel="noopener noreferrer"`)
			}
			b.WriteString(">")
		case xhtml.EndTagToken:
			name, _ := z.TagName()
			n := strings.ToLower(string(name))
			if droppedTags[n] {
				if drop > 0 {
					drop--
				}
				continue
			}
			if drop == 0 && allowedTags[n] && n != "br" && n != "img" && n != "hr" && n != "col" {
				b.WriteString("</" + n + ">")
			}
		}
	}
}

// HTMLToText turns HTML into plain text (for replies and previews).
func HTMLToText(in string) string {
	z := xhtml.NewTokenizer(strings.NewReader(in))
	var b strings.Builder
	drop := 0
	for {
		switch z.Next() {
		case xhtml.ErrorToken:
			return strings.TrimSpace(collapseBlank(b.String()))
		case xhtml.TextToken:
			if drop == 0 {
				b.Write(z.Text())
			}
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			name, _ := z.TagName()
			n := string(name)
			if droppedTags[n] {
				drop++
			}
			switch n {
			case "br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "blockquote":
				b.WriteString("\n")
			}
		case xhtml.EndTagToken:
			name, _ := z.TagName()
			if droppedTags[string(name)] && drop > 0 {
				drop--
			}
		}
	}
}

func collapseBlank(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	blank := 0
	for _, l := range lines {
		l = strings.TrimRight(l, " \t\r")
		if strings.TrimSpace(l) == "" {
			blank++
			if blank > 1 {
				continue
			}
		} else {
			blank = 0
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
