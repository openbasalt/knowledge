package index

import (
	"reflect"
	"testing"

	"github.com/openbasalt/knowledge/internal/source"
	"github.com/openbasalt/knowledge/protocol"
)

func seed(t *testing.T) *Index {
	t.Helper()
	src, err := source.Load("../../content/basalt")
	if err != nil {
		t.Fatal(err)
	}
	return New(src.Entries)
}

func ids(hits []Hit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.Entry.ID)
	}
	return out
}

func TestSearch(t *testing.T) {
	ix := seed(t)
	gpu := func(dev string) []protocol.HardwareID {
		return []protocol.HardwareID{{Bus: "pci", Vendor: "10de", Device: dev}}
	}
	cases := []struct {
		name  string
		req   protocol.SearchRequest
		first string
		not   string
	}{
		{"gtx 1070", protocol.SearchRequest{Intent: "driver.install", Hardware: gpu("1b81")}, "nvidia-legacy-580", ""},
		{"rtx 4060", protocol.SearchRequest{Intent: "driver.install", Hardware: gpu("2882")}, "nvidia-which-driver", "nvidia-legacy-580"},
		{"error code", protocol.SearchRequest{Errors: []string{"EKEYREJECTED"}}, "secure-boot-module-rejected", ""},
		{"free text pt", protocol.SearchRequest{FreeText: &protocol.FreeText{Text: "disco cheio, journal grande", Consent: "question"}}, "journal-disk-usage", ""},
		{"free text en", protocol.SearchRequest{FreeText: &protocol.FreeText{Text: "nginx 403 forbidden", Consent: "question"}}, "selinux-web-content-label", ""},
		{"other distro", protocol.SearchRequest{Distro: "debian", Errors: []string{"EKEYREJECTED"}}, "", "secure-boot-module-rejected"},
	}
	for _, c := range cases {
		hits := ix.Search(&c.req)
		got := ids(hits)
		if c.first != "" && (len(got) == 0 || got[0] != c.first) {
			t.Errorf("%s: %v, want %s first", c.name, got, c.first)
		}
		for _, id := range got {
			if id == c.not {
				t.Errorf("%s: %s must not be returned", c.name, c.not)
			}
		}
	}
	// No relevance, no result: a bare distro matches nothing.
	if hits := ix.Search(&protocol.SearchRequest{Distro: "basalt", Intent: "unrelated.thing"}); len(hits) != 0 {
		t.Errorf("irrelevant query returned %v", ids(hits))
	}
	// Deterministic.
	r := protocol.SearchRequest{Intent: "diagnose", Limit: 10}
	if a, b := ids(ix.Search(&r)), ids(ix.Search(&r)); !reflect.DeepEqual(a, b) {
		t.Errorf("ranking differs: %v %v", a, b)
	}
}

func TestTokens(t *testing.T) {
	got := Tokens("Meu VÍDEO não funciona com a GTX-1070!")
	want := []string{"video", "nao", "funciona", "gtx", "1070"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%v", got)
	}
}
