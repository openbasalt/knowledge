// Package protocol defines the wire format of the knowledge protocol,
// version 0: the signed objects (entries, packs, catalogs), the search
// request and response, discovery and errors, with strict validation.
// docs/protocol.md is the normative description; the JSON schemas in
// schemas/ describe the same shapes.
package protocol

import (
	"time"

	"github.com/openbasalt/knowledge/signing"
)

// Version is the protocol version this package implements.
const Version = "0"

// Supported lists the protocol versions this implementation speaks.
var Supported = []string{Version}

// Payload types (the envelope's payloadType).
const (
	TypeEntry     = "application/vnd.openbasalt.knowledge.entry+json"
	TypePack      = "application/vnd.openbasalt.knowledge.pack+json"
	TypeCatalog   = "application/vnd.openbasalt.knowledge.catalog+json"
	TypeSearch    = "application/vnd.openbasalt.knowledge.search-response+json"
	TypeDiscovery = "application/vnd.openbasalt.knowledge.discovery+json"
	TypeError     = "application/vnd.openbasalt.knowledge.error+json"
)

// Schemas (the "schema" member of every payload and request).
const (
	SchemaEntry     = "kb.entry/v0"
	SchemaPack      = "kb.pack/v0"
	SchemaCatalog   = "kb.catalog/v0"
	SchemaRequest   = "kb.search.request/v0"
	SchemaResponse  = "kb.search.response/v0"
	SchemaDiscovery = "kb.discovery/v0"
	SchemaError     = "kb.error/v0"
)

// MediaType is the Content-Type of every protocol body (envelopes and the
// search request).
const MediaType = "application/json"

// Limits of a search request.
const (
	MaxRequestBytes = 8 << 10
	MaxHardware     = 8
	MaxPackages     = 16
	MaxErrors       = 8
	MaxFreeText     = 280
	MaxResults      = 10
	DefaultResults  = 5
)

// CorePack is the pack that holds the entries every machine gets.
const CorePack = "core"

// Conditions say where an entry or a pack applies. Every group that is
// present must be satisfied; an empty group says nothing. See Match.
type Conditions struct {
	Distros  []string        `json:"distros,omitempty"`  // os-release ID values
	Releases *Range          `json:"releases,omitempty"` // os-release VERSION_ID range
	Arch     []string        `json:"arch,omitempty"`     // e.g. x86_64, aarch64
	Hardware []HardwareMatch `json:"hardware,omitempty"` // any one must match
	Packages []PackageMatch  `json:"packages,omitempty"` // see Match
}

// Range is an inclusive version range; either end may be empty.
type Range struct {
	Min string `json:"min,omitempty"`
	Max string `json:"max,omitempty"`
}

// HardwareMatch matches devices of one vendor on one bus by device id
// ranges (inclusive, four lower case hex digits).
type HardwareMatch struct {
	Bus     string    `json:"bus"`    // pci or usb
	Vendor  string    `json:"vendor"` // four hex digits
	Devices []IDRange `json:"devices,omitempty"`
}

// IDRange is an inclusive range of device ids.
type IDRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// PackageMatch matches an installed package by name and version range.
type PackageMatch struct {
	Name string `json:"name"`
	Min  string `json:"min,omitempty"`
	Max  string `json:"max,omitempty"`
}

// Proposal is one step an entry suggests, expressed only as an action of
// the client's closed action set (English identifier and parameters). A
// client that does not know the action shows the step as text and never
// runs anything for it.
type Proposal struct {
	ID       string            `json:"id"`
	Action   string            `json:"action"`
	Params   map[string]string `json:"params,omitempty"`
	Risk     string            `json:"risk"` // low, medium, high
	Requires []string          `json:"requires,omitempty"`
}

// Variant is the human text of an entry in one language.
type Variant struct {
	Title     string            `json:"title"`
	Summary   string            `json:"summary"`
	Body      string            `json:"body"` // Markdown
	Proposals map[string]string `json:"proposals,omitempty"`
}

// Reference is a source an entry is based on.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Entry is one knowledge article, signed by the namespace's publisher.
type Entry struct {
	Schema     string             `json:"schema"`
	Namespace  string             `json:"namespace"`
	ID         string             `json:"id"`
	Revision   int                `json:"revision"`
	Updated    string             `json:"updated"` // YYYY-MM-DD
	Pack       string             `json:"pack"`
	Kind       string             `json:"kind"` // guide, fix, reference
	Intents    []string           `json:"intents,omitempty"`
	Components []string           `json:"components,omitempty"`
	Errors     []string           `json:"errors,omitempty"`
	Keywords   []string           `json:"keywords,omitempty"`
	AppliesTo  Conditions         `json:"applies_to"`
	Proposals  []Proposal         `json:"proposals,omitempty"`
	Variants   map[string]Variant `json:"variants"`
	References []Reference        `json:"references,omitempty"`
	License    string             `json:"license"`
}

// Pack is a signed set of entries a client can download and use offline.
type Pack struct {
	Schema    string              `json:"schema"`
	Namespace string              `json:"namespace"`
	ID        string              `json:"id"`
	Version   string              `json:"version"`
	Created   time.Time           `json:"created"`
	AppliesTo Conditions          `json:"applies_to"`
	Entries   []*signing.Envelope `json:"entries"`
}

// CatalogPack describes one pack in the catalog.
type CatalogPack struct {
	ID           string            `json:"id"`
	Version      string            `json:"version"`
	Path         string            `json:"path"`   // relative to the namespace root
	Size         int64             `json:"size"`   // bytes of the pack file
	Digest       string            `json:"digest"` // sha256 of the pack file bytes
	Entries      int               `json:"entries"`
	AppliesTo    Conditions        `json:"applies_to"`
	Titles       map[string]string `json:"titles"`
	Descriptions map[string]string `json:"descriptions"`
}

// Catalog lists the packs of a namespace, signed by its publisher.
type Catalog struct {
	Schema    string        `json:"schema"`
	Namespace string        `json:"namespace"`
	Version   string        `json:"version"`
	Created   time.Time     `json:"created"`
	Packs     []CatalogPack `json:"packs"`
}

// HardwareID is one device of the machine.
type HardwareID struct {
	Bus    string `json:"bus"`
	Vendor string `json:"vendor"`
	Device string `json:"device"`
}

// PackageVersion is one installed package.
type PackageVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// FreeText is text the person typed, sent only when the person allowed it
// for this question or this topic. Servers never log it.
type FreeText struct {
	Text    string `json:"text"`
	Consent string `json:"consent"` // question or topic
}

// SearchRequest is the minimized, structured query a client sends.
type SearchRequest struct {
	Schema    string           `json:"schema"`
	Namespace string           `json:"namespace"`
	Distro    string           `json:"distro,omitempty"`
	Release   string           `json:"release,omitempty"`
	Arch      string           `json:"arch,omitempty"`
	Intent    string           `json:"intent,omitempty"`
	Component string           `json:"component,omitempty"`
	Hardware  []HardwareID     `json:"hardware,omitempty"`
	Packages  []PackageVersion `json:"packages,omitempty"`
	Errors    []string         `json:"errors,omitempty"`
	Lang      string           `json:"lang,omitempty"`
	FreeText  *FreeText        `json:"free_text,omitempty"`
	Limit     int              `json:"limit,omitempty"`
	Nonce     string           `json:"nonce"`
}

// BundleRef identifies the content a server answers from.
type BundleRef struct {
	Version string `json:"version"`
	Digest  string `json:"digest"` // digest of the catalog payload
}

// Result is one search hit. The entry itself is the publisher-signed
// envelope; the server only adds the rank.
type Result struct {
	ID      string            `json:"id"`
	Score   float64           `json:"score"`
	Digest  string            `json:"digest"` // digest of the entry payload
	Pack    string            `json:"pack"`
	Matched []string          `json:"matched,omitempty"`
	Entry   *signing.Envelope `json:"entry"`
}

// PackRef points to a pack whose conditions match the query.
type PackRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// SearchResponse is signed by the server's delegated online key.
type SearchResponse struct {
	Schema        string    `json:"schema"`
	Namespace     string    `json:"namespace"`
	RequestDigest string    `json:"request_digest"`
	Nonce         string    `json:"nonce"`
	IssuedAt      time.Time `json:"issued_at"`
	Bundle        BundleRef `json:"bundle"`
	Results       []Result  `json:"results"`
	Packs         []PackRef `json:"packs,omitempty"`
}

// RateLimit describes the server's per-client limit.
type RateLimit struct {
	Requests int `json:"requests"`
	Seconds  int `json:"seconds"`
	Burst    int `json:"burst"`
}

// Limits advertises the server's request limits.
type Limits struct {
	MaxRequestBytes int       `json:"max_request_bytes"`
	MaxResults      int       `json:"max_results"`
	RateLimit       RateLimit `json:"rate_limit"`
}

// NamespaceInfo describes one namespace a server serves.
type NamespaceInfo struct {
	Name       string            `json:"name"`
	Languages  []string          `json:"languages"`
	Bundle     BundleRef         `json:"bundle"`
	Keyring    int               `json:"keyring_version"`
	Delegation *signing.Envelope `json:"delegation"`
}

// Discovery is the server's description of itself, signed by its online
// key (each namespace's delegation shows the key may speak for it).
type Discovery struct {
	Schema     string          `json:"schema"`
	Versions   []string        `json:"versions"`
	IssuedAt   time.Time       `json:"issued_at"`
	Namespaces []NamespaceInfo `json:"namespaces"`
	Limits     Limits          `json:"limits"`
	Privacy    []string        `json:"privacy"`
}

// Error codes.
const (
	ErrInvalidRequest     = "invalid_request"
	ErrUnsupportedVersion = "unsupported_version"
	ErrUnknownNamespace   = "unknown_namespace"
	ErrNotFound           = "not_found"
	ErrRateLimited        = "rate_limited"
	ErrTooLarge           = "payload_too_large"
	ErrFreeTextConsent    = "free_text_without_consent"
	ErrMethod             = "method_not_allowed"
	ErrMediaType          = "unsupported_media_type"
	ErrInternal           = "internal"
)

// Error is the body of every error response.
type Error struct {
	Schema     string   `json:"schema"`
	Code       string   `json:"code"`
	Message    string   `json:"message"` // English, for developers, never shown as content
	RetryAfter int      `json:"retry_after,omitempty"`
	Supported  []string `json:"supported_versions,omitempty"`
}
