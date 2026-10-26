package protocol

import (
	"strings"
	"testing"
)

// globe is an icon in the style the UI's built-in icons use.
const globe = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <circle cx="12" cy="12" r="9"/>
  <ellipse cx="12" cy="12" rx="4" ry="9"/>
  <path d="M3 12h18"/>
</svg>`

func TestValidateIcon(t *testing.T) {
	valid := map[string]string{
		"stroked shapes": globe,
		"declaration, comments, references to its own elements": `<?xml version="1.0" encoding="UTF-8"?>
<!-- a dummy -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 24 24">
  <title>BOB</title>
  <defs>
    <linearGradient id="g"><stop offset="0" stop-color="#000"/><stop offset="1" stop-opacity="0.5"/></linearGradient>
    <clipPath id="c"><rect width="24" height="24" rx="4"/></clipPath>
    <symbol id="s"><circle cx="5" cy="5" r="4"/></symbol>
  </defs>
  <g clip-path="url(#c)" style="fill: url('#g')">
    <use href="#s"/><use xlink:href="#s" x="12"/>
    <text x="2" y="20">HTTP</text>
  </g>
</svg>`,
	}
	for name, svg := range valid {
		if err := ValidateIcon(svg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	svg := func(body string) string {
		return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">` + body + `</svg>`
	}
	for _, c := range []struct{ name, svg, want string }{
		{"empty", "  ", "empty"},
		{"too large", svg(strings.Repeat(`<path d="M0 0h1"/>`, MaxIconSize/16)), "larger than"},
		{"not XML", "<svg", "well-formed"},
		{"not SVG", `<html xmlns="http://www.w3.org/1999/xhtml"></html>`, "root element must be"},
		{"no namespace", `<svg viewBox="0 0 24 24"><path d="M0 0"/></svg>`, "root element must be"},
		{"two roots", svg("") + svg(""), "more than one root"},
		{"text after the root", svg("") + "boo", "outside its root"},
		{"script", svg(`<script>alert(1)</script>`), "<script> is not allowed"},
		{"foreignObject", svg(`<foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject>`), "<foreignObject> is not allowed"},
		{"image", svg(`<image href="#x"/>`), "<image> is not allowed"},
		{"style element", svg(`<style>@import url(https://evil.example/x.css);</style>`), "<style> is not allowed"},
		{"animation", svg(`<animate attributeName="href" to="javascript:alert(1)"/>`), "<animate> is not allowed"},
		{"another namespace", svg(`<x:path xmlns:x="urn:other" d="M0 0"/>`), "is not allowed"},
		{"event handler", svg(`<path d="M0 0" onclick="alert(1)"/>`), "onclick"},
		{"event handler, any case", `<svg xmlns="http://www.w3.org/2000/svg" ONLOAD="alert(1)"/>`, "ONLOAD"},
		{"external href", svg(`<use href="https://evil.example/s.svg#s"/>`), `href="#id"`},
		{"javascript href", svg(`<use xlink:href="javascript:alert(1)" xmlns:xlink="http://www.w3.org/1999/xlink"/>`), `href="#id"`},
		{"external url()", svg(`<path d="M0 0" fill="url(https://evil.example/p.svg#g)"/>`), "url(#id)"},
		{"external url() in style", svg(`<path d="M0 0" style="fill: url( 'data:image/png;base64,AA')"/>`), "url(#id)"},
		{"DOCTYPE", `<!DOCTYPE svg [<!ENTITY x "y">]>` + svg(""), "DOCTYPE"},
		{"processing instruction", `<?xml-stylesheet href="https://evil.example/x.css"?>` + svg(""), "xml-stylesheet"},
	} {
		err := ValidateIcon(c.svg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error containing %q", c.name, err, c.want)
		}
	}
}
