package protocol

import (
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0}, {"1.0", "1.1", -1}, {"1.10", "1.9", 1}, {"44", "43", 1},
		{"6.17.1", "6.9.12", 1}, {"1.0a", "1.0", 1}, {"1.0", "1.0a", -1}, {"1a", "1.0", -1},
		{"1.0~rc1", "1.0", -1}, {"1.0~rc1", "1.0~rc2", -1}, {"1.0^git1", "1.0", 1}, {"1.0^git1", "1.0.1", -1},
		{"580.178.04", "580.95.05", 1}, {"001", "1", 0}, {"1.0.", "1.0", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestMatch(t *testing.T) {
	legacy := Conditions{
		Distros:  []string{"basalt", "fedora"},
		Releases: &Range{Min: "43", Max: "45"},
		Hardware: []HardwareMatch{{Bus: "pci", Vendor: "10de", Devices: []IDRange{{From: "1b00", To: "1bff"}}}},
		Packages: []PackageMatch{{Name: "kernel", Min: "6.0"}},
	}
	gtx := HardwareID{Bus: "pci", Vendor: "10de", Device: "1b81"}
	rtx := HardwareID{Bus: "pci", Vendor: "10de", Device: "2882"}
	cases := []struct {
		name     string
		f        Facts
		excluded bool
		matched  string
	}{
		{"nothing known", Facts{}, false, ""},
		{"gtx", Facts{Hardware: []HardwareID{gtx}}, false, "hardware"},
		{"rtx", Facts{Hardware: []HardwareID{rtx}}, true, ""},
		{"gtx and rtx", Facts{Hardware: []HardwareID{rtx, gtx}}, false, "hardware"},
		{"other distro", Facts{Distro: "debian", Hardware: []HardwareID{gtx}}, true, ""},
		{"release too old", Facts{Release: "42"}, true, ""},
		{"release ok", Facts{Distro: "basalt", Release: "44"}, false, "distro,release"},
		{"kernel too old", Facts{Packages: []PackageVersion{{Name: "kernel", Version: "5.14.0"}}}, true, ""},
		{"kernel ok", Facts{Packages: []PackageVersion{{Name: "kernel", Version: "6.17.1"}}}, false, "packages"},
		{"package not named", Facts{Packages: []PackageVersion{{Name: "bash", Version: "5"}}}, false, ""},
	}
	for _, c := range cases {
		m := legacy.Match(c.f)
		if m.Excluded != c.excluded || strings.Join(m.Matched, ",") != c.matched {
			t.Errorf("%s: excluded=%v matched=%v", c.name, m.Excluded, m.Matched)
		}
	}
}

func validRequest() SearchRequest {
	return SearchRequest{Schema: SchemaRequest, Namespace: "basalt", Intent: "driver.install", Nonce: "AAAAAAAAAAAAAAAAAAAAAA"}
}

func TestRequestValidation(t *testing.T) {
	bad := map[string]func(r *SearchRequest){
		"schema":           func(r *SearchRequest) { r.Schema = "x" },
		"namespace":        func(r *SearchRequest) { r.Namespace = "Basalt OS" },
		"empty query":      func(r *SearchRequest) { r.Intent = "" },
		"intent sentence":  func(r *SearchRequest) { r.Intent = "install the driver" },
		"error sentence":   func(r *SearchRequest) { r.Errors = []string{"my disk is full"} },
		"hex":              func(r *SearchRequest) { r.Hardware = []HardwareID{{Bus: "pci", Vendor: "10DE", Device: "1b81"}} },
		"bus":              func(r *SearchRequest) { r.Hardware = []HardwareID{{Bus: "isa", Vendor: "10de", Device: "1b81"}} },
		"too many errors":  func(r *SearchRequest) { r.Errors = strings.Split("a,b,c,d,e,f,g,h,i", ",") },
		"no consent":       func(r *SearchRequest) { r.FreeText = &FreeText{Text: "hi"} },
		"long text":        func(r *SearchRequest) { r.FreeText = &FreeText{Text: strings.Repeat("a", 281), Consent: "topic"} },
		"control in text":  func(r *SearchRequest) { r.FreeText = &FreeText{Text: "a\x1bb", Consent: "topic"} },
		"short nonce":      func(r *SearchRequest) { r.Nonce = "abc" },
		"limit":            func(r *SearchRequest) { r.Limit = 11 },
		"lang":             func(r *SearchRequest) { r.Lang = "portuguese" },
		"package with sep": func(r *SearchRequest) { r.Packages = []PackageVersion{{Name: "a b"}} },
	}
	for name, mut := range bad {
		r := validRequest()
		mut(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	r := validRequest()
	r.FreeText = &FreeText{Text: "meu vídeo não funciona", Consent: "question"}
	r.Lang = "pt-BR"
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRequest([]byte(`{"schema":"kb.search.request/v0","namespace":"basalt","intent":"x","nonce":"AAAAAAAAAAAAAAAAAAAAAA","hostname":"maria-laptop"}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := ParseRequest([]byte(`{"schema":"kb.search.request/v0","namespace":"basalt","intent":"x","nonce":"AAAAAAAAAAAAAAAAAAAAAA"} {}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestEntryText(t *testing.T) {
	e := Entry{Variants: map[string]Variant{"en": {Title: "en"}, "pt-BR": {Title: "pt"}}}
	for lang, want := range map[string]string{"pt-BR": "pt", "pt": "pt", "pt-PT": "pt", "de": "en", "": "en"} {
		if v, _ := e.Text(lang); v.Title != want {
			t.Errorf("%s: %s", lang, v.Title)
		}
	}
}

func TestParse(t *testing.T) {
	if h, err := ParseHardwareID("PCI:10DE:1B81"); err != nil || h.Device != "1b81" {
		t.Fatal(h, err)
	}
	for _, s := range []string{"pci:10de", "pci:10de:1b8", "isa:10de:1b81"} {
		if _, err := ParseHardwareID(s); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
	if p, err := ParsePackage("kernel=6.17.1-200.fc44"); err != nil || p.Version != "6.17.1-200.fc44" {
		t.Fatal(p, err)
	}
}
