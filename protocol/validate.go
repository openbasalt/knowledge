package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openbasalt/knowledge/signing"
)

var (
	reID         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)
	reIdent      = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)
	reAction     = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)
	reParam      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	reErrorCode  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,79}$`)
	rePkgName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	rePkgVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~^:-]{0,63}$`)
	reHex4       = regexp.MustCompile(`^[0-9a-f]{4}$`)
	reLang       = regexp.MustCompile(`^[a-z]{2,3}(-[A-Z]{2}|-[A-Z][a-z]{3})?$`)
	reDistro     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	reRelease    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~^-]{0,31}$`)
	reArch       = regexp.MustCompile(`^[a-z0-9_]{1,16}$`)
	reDate       = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reVersion    = regexp.MustCompile(`^[0-9][0-9.]{0,31}$`)
	reDigest     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ValidID reports whether s is a valid entry or pack id.
func ValidID(s string) bool { return reID.MatchString(s) }

// ValidIdent reports whether s is a valid intent or component identifier.
func ValidIdent(s string) bool { return len(s) <= 64 && reIdent.MatchString(s) }

// ValidAction reports whether s has the shape of an action identifier.
func ValidAction(s string) bool { return len(s) <= 64 && reAction.MatchString(s) }

// ValidLang reports whether s is an accepted language tag (en, pt-BR,
// zh-Hant).
func ValidLang(s string) bool { return reLang.MatchString(s) }

// ValidErrorCode reports whether s is an accepted error code: no spaces,
// so a sentence (and the personal data it may hold) cannot be sent as one.
func ValidErrorCode(s string) bool { return reErrorCode.MatchString(s) }

// DecodeStrict decodes exactly one JSON value into v, rejecting unknown
// fields and trailing data.
func DecodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

// RequestError is a validation failure with its protocol error code.
type RequestError struct {
	Code string
	Msg  string
}

func (e *RequestError) Error() string { return e.Code + ": " + e.Msg }

func invalid(format string, a ...any) error {
	return &RequestError{Code: ErrInvalidRequest, Msg: fmt.Sprintf(format, a...)}
}

// ParseRequest decodes and validates a search request body.
func ParseRequest(b []byte) (*SearchRequest, error) {
	if len(b) > MaxRequestBytes {
		return nil, &RequestError{Code: ErrTooLarge, Msg: "request body too large"}
	}
	var r SearchRequest
	if err := DecodeStrict(b, &r); err != nil {
		return nil, invalid("%v", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Validate checks a search request.
func (r *SearchRequest) Validate() error {
	if r.Schema != SchemaRequest {
		return invalid("schema %q: want %q", r.Schema, SchemaRequest)
	}
	if !signing.ValidNamespace(r.Namespace) {
		return invalid("namespace is not valid")
	}
	if r.Distro != "" && !reDistro.MatchString(r.Distro) {
		return invalid("distro is not valid")
	}
	if r.Release != "" && !reRelease.MatchString(r.Release) {
		return invalid("release is not valid")
	}
	if r.Arch != "" && !reArch.MatchString(r.Arch) {
		return invalid("arch is not valid")
	}
	if r.Intent != "" && !ValidIdent(r.Intent) {
		return invalid("intent is not an identifier")
	}
	if r.Component != "" && !ValidIdent(r.Component) {
		return invalid("component is not an identifier")
	}
	if len(r.Hardware) > MaxHardware {
		return invalid("at most %d hardware ids", MaxHardware)
	}
	for _, h := range r.Hardware {
		if h.Bus != "pci" && h.Bus != "usb" {
			return invalid("hardware bus must be pci or usb")
		}
		if !reHex4.MatchString(h.Vendor) || !reHex4.MatchString(h.Device) {
			return invalid("hardware vendor and device are four lower case hex digits")
		}
	}
	if len(r.Packages) > MaxPackages {
		return invalid("at most %d packages", MaxPackages)
	}
	for _, p := range r.Packages {
		if !rePkgName.MatchString(p.Name) {
			return invalid("package name is not valid")
		}
		if p.Version != "" && !rePkgVersion.MatchString(p.Version) {
			return invalid("package version is not valid")
		}
	}
	if len(r.Errors) > MaxErrors {
		return invalid("at most %d error codes", MaxErrors)
	}
	for _, e := range r.Errors {
		if !ValidErrorCode(e) {
			return invalid("error codes are identifiers without spaces")
		}
	}
	if r.Lang != "" && !ValidLang(r.Lang) {
		return invalid("lang is not a supported language tag")
	}
	if r.FreeText != nil {
		if r.FreeText.Consent != "question" && r.FreeText.Consent != "topic" {
			return &RequestError{Code: ErrFreeTextConsent, Msg: "free text needs consent: question or topic"}
		}
		if t := r.FreeText.Text; t == "" || utf8.RuneCountInString(t) > MaxFreeText || !utf8.ValidString(t) {
			return invalid("free text must be 1 to %d characters", MaxFreeText)
		}
		for _, c := range r.FreeText.Text {
			if unicode.IsControl(c) && c != ' ' {
				return invalid("free text holds control characters")
			}
		}
	}
	if r.Limit < 0 || r.Limit > MaxResults {
		return invalid("limit must be 1 to %d", MaxResults)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(r.Nonce)
	if err != nil || len(nonce) < 16 || len(nonce) > 32 {
		return invalid("nonce must be 16 to 32 random bytes, base64url without padding")
	}
	if r.Intent == "" && r.Component == "" && len(r.Hardware) == 0 && len(r.Packages) == 0 &&
		len(r.Errors) == 0 && r.FreeText == nil {
		return invalid("a query needs an intent, component, hardware, package, error code or free text")
	}
	return nil
}

func validConditions(c Conditions) error {
	for _, d := range c.Distros {
		if !reDistro.MatchString(d) {
			return fmt.Errorf("distro %q is not valid", d)
		}
	}
	if c.Releases != nil {
		if c.Releases.Min == "" && c.Releases.Max == "" {
			return errors.New("releases range is empty")
		}
		for _, v := range []string{c.Releases.Min, c.Releases.Max} {
			if v != "" && !reRelease.MatchString(v) {
				return fmt.Errorf("release %q is not valid", v)
			}
		}
		if c.Releases.Min != "" && c.Releases.Max != "" && CompareVersions(c.Releases.Min, c.Releases.Max) > 0 {
			return errors.New("releases min is above max")
		}
	}
	for _, a := range c.Arch {
		if !reArch.MatchString(a) {
			return fmt.Errorf("arch %q is not valid", a)
		}
	}
	for _, h := range c.Hardware {
		if h.Bus != "pci" && h.Bus != "usb" {
			return fmt.Errorf("hardware bus %q: pci or usb", h.Bus)
		}
		if !reHex4.MatchString(h.Vendor) {
			return fmt.Errorf("hardware vendor %q: four lower case hex digits", h.Vendor)
		}
		for _, r := range h.Devices {
			if !reHex4.MatchString(r.From) || !reHex4.MatchString(r.To) || r.From > r.To {
				return fmt.Errorf("hardware range %s-%s is not valid", r.From, r.To)
			}
		}
	}
	for _, p := range c.Packages {
		if !rePkgName.MatchString(p.Name) {
			return fmt.Errorf("package %q is not valid", p.Name)
		}
		for _, v := range []string{p.Min, p.Max} {
			if v != "" && !rePkgVersion.MatchString(v) {
				return fmt.Errorf("package version %q is not valid", v)
			}
		}
	}
	return nil
}

func validText(s string, max int) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return false
		}
	}
	return true
}

// Validate checks an entry. Machine fields are English identifiers; every
// language variant carries the human text for every proposal.
func (e *Entry) Validate() error {
	if e.Schema != SchemaEntry {
		return fmt.Errorf("schema %q: want %q", e.Schema, SchemaEntry)
	}
	if !signing.ValidNamespace(e.Namespace) {
		return fmt.Errorf("namespace %q is not valid", e.Namespace)
	}
	if !ValidID(e.ID) {
		return fmt.Errorf("id %q is not valid", e.ID)
	}
	if e.Revision < 1 {
		return errors.New("revision must be 1 or more")
	}
	if !reDate.MatchString(e.Updated) {
		return errors.New("updated must be YYYY-MM-DD")
	}
	if _, err := time.Parse(time.DateOnly, e.Updated); err != nil {
		return fmt.Errorf("updated: %v", err)
	}
	if !ValidID(e.Pack) {
		return fmt.Errorf("pack %q is not valid", e.Pack)
	}
	if !slices.Contains([]string{"guide", "fix", "reference"}, e.Kind) {
		return fmt.Errorf("kind %q: guide, fix or reference", e.Kind)
	}
	for _, list := range [][]string{e.Intents, e.Components} {
		for _, s := range list {
			if !ValidIdent(s) {
				return fmt.Errorf("identifier %q is not valid", s)
			}
		}
	}
	for _, s := range e.Errors {
		if !ValidErrorCode(s) {
			return fmt.Errorf("error code %q is not valid", s)
		}
	}
	for _, s := range e.Keywords {
		if !validText(s, 64) || strings.ContainsAny(s, "\n\t") {
			return fmt.Errorf("keyword %q is not valid", s)
		}
	}
	if err := validConditions(e.AppliesTo); err != nil {
		return fmt.Errorf("applies_to: %v", err)
	}
	ids := map[string]bool{}
	for _, p := range e.Proposals {
		if !ValidID(p.ID) || ids[p.ID] {
			return fmt.Errorf("proposal id %q is not valid or repeated", p.ID)
		}
		if !ValidAction(p.Action) {
			return fmt.Errorf("proposal %s: action %q is not an identifier", p.ID, p.Action)
		}
		if !slices.Contains([]string{"low", "medium", "high"}, p.Risk) {
			return fmt.Errorf("proposal %s: risk must be low, medium or high", p.ID)
		}
		for k, v := range p.Params {
			if !reParam.MatchString(k) || !validText(v, 256) || strings.ContainsAny(v, "\n\t") {
				return fmt.Errorf("proposal %s: parameter %q is not valid", p.ID, k)
			}
		}
		for _, r := range p.Requires {
			if !ids[r] {
				return fmt.Errorf("proposal %s requires %q, which is not an earlier proposal", p.ID, r)
			}
		}
		ids[p.ID] = true
	}
	if _, ok := e.Variants["en"]; !ok {
		return errors.New("an English (en) variant is required")
	}
	for lang, v := range e.Variants {
		if !ValidLang(lang) {
			return fmt.Errorf("variant language %q is not valid", lang)
		}
		if !validText(v.Title, 120) || !validText(v.Summary, 400) || !validText(v.Body, 32<<10) {
			return fmt.Errorf("variant %s: title, summary and body are required and bounded", lang)
		}
		for id := range ids {
			if !validText(v.Proposals[id], 300) {
				return fmt.Errorf("variant %s: no text for proposal %s", lang, id)
			}
		}
		for id := range v.Proposals {
			if !ids[id] {
				return fmt.Errorf("variant %s: text for unknown proposal %s", lang, id)
			}
		}
	}
	for _, r := range e.References {
		u, err := url.Parse(r.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || !validText(r.Title, 200) {
			return fmt.Errorf("reference %q must be an https URL with a title", r.URL)
		}
	}
	if e.License == "" {
		return errors.New("license is required")
	}
	return nil
}

// Validate checks a pack (not the signatures of its entries).
func (p *Pack) Validate() error {
	if p.Schema != SchemaPack {
		return fmt.Errorf("schema %q: want %q", p.Schema, SchemaPack)
	}
	if !signing.ValidNamespace(p.Namespace) || !ValidID(p.ID) {
		return errors.New("pack namespace or id is not valid")
	}
	if !reVersion.MatchString(p.Version) {
		return fmt.Errorf("pack version %q is not valid", p.Version)
	}
	if err := validConditions(p.AppliesTo); err != nil {
		return fmt.Errorf("applies_to: %v", err)
	}
	if len(p.Entries) == 0 {
		return errors.New("pack has no entries")
	}
	return nil
}

// Validate checks a catalog.
func (c *Catalog) Validate() error {
	if c.Schema != SchemaCatalog {
		return fmt.Errorf("schema %q: want %q", c.Schema, SchemaCatalog)
	}
	if !signing.ValidNamespace(c.Namespace) || !reVersion.MatchString(c.Version) {
		return errors.New("catalog namespace or version is not valid")
	}
	seen := map[string]bool{}
	for _, p := range c.Packs {
		if !ValidID(p.ID) || seen[p.ID] {
			return fmt.Errorf("catalog pack %q is not valid or repeated", p.ID)
		}
		seen[p.ID] = true
		if !reVersion.MatchString(p.Version) || !reDigest.MatchString(p.Digest) || p.Size <= 0 || p.Entries <= 0 {
			return fmt.Errorf("catalog pack %s: version, digest, size or entries not valid", p.ID)
		}
		if p.Path != PackPath(p.ID, p.Version) {
			return fmt.Errorf("catalog pack %s: path %q: want %q", p.ID, p.Path, PackPath(p.ID, p.Version))
		}
		if err := validConditions(p.AppliesTo); err != nil {
			return fmt.Errorf("catalog pack %s: %v", p.ID, err)
		}
		if p.Titles["en"] == "" || p.Descriptions["en"] == "" {
			return fmt.Errorf("catalog pack %s: English title and description required", p.ID)
		}
	}
	return nil
}

// PackPath is where a pack file lives under the namespace root.
func PackPath(id, version string) string { return "packs/" + id + "-" + version + ".json" }

// EntryPath is where an entry file lives under the namespace root.
func EntryPath(id string) string { return "entries/" + id + ".json" }

// KeyringPath is where a keyring version lives under the namespace root.
func KeyringPath(version int) string { return fmt.Sprintf("keyring/%d.json", version) }
