package protocol

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

var rePromise = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Service promises a conforming server makes about its own process
// (section 7.1 of the protocol). Clients may require the first three.
const (
	PromiseNoAccounts      = "no-accounts"
	PromiseNoCookies       = "no-cookies"
	PromiseNoAddresses     = "no-client-addresses-stored"
	PromiseNoQueryLogging  = "no-query-logging"
	PromiseAggregateCounts = "aggregate-counters-only"
)

// ServicePromises is the list a conforming server publishes.
var ServicePromises = []string{
	PromiseNoAccounts,
	PromiseNoCookies,
	PromiseNoAddresses,
	PromiseNoQueryLogging,
	PromiseAggregateCounts,
}

// RequiredPromises are the service promises a client may refuse to do
// without (and the conformance suite requires).
var RequiredPromises = []string{PromiseNoAccounts, PromiseNoCookies, PromiseNoQueryLogging}

// AccessLogFields are the fields a hosting layer's access log may hold.
var AccessLogFields = []string{"ip", "time", "method", "path", "status", "size", "duration", "host", "user_agent", "referer"}

// MaxRetentionDays bounds hosting.retention_days.
const MaxRetentionDays = 3650

// Privacy is the discovery privacy section: what the service itself
// promises, and what the operator states about the hosting layer in
// front of it (proxies, ingress, load balancers), which the service
// cannot control.
type Privacy struct {
	Service []string `json:"service"`
	Hosting Hosting  `json:"hosting"`
}

// Hosting holds the operator's statement about the hosting layer. When
// Declared is false the operator said nothing, and a client must assume
// the host may keep client addresses for an unknown time. When Declared
// is true, AccessLogs and QueryBodyLogged are present; RetentionDays and
// Fields are present exactly when AccessLogs is true.
type Hosting struct {
	Declared        bool     `json:"declared"`
	Provider        string   `json:"provider,omitempty"`
	AccessLogs      *bool    `json:"access_logs,omitempty"`
	RetentionDays   *int     `json:"retention_days,omitempty"`
	Fields          []string `json:"fields,omitempty"`
	QueryBodyLogged *bool    `json:"query_body_logged,omitempty"`
}

// Validate checks the privacy section.
func (p *Privacy) Validate() error {
	seen := map[string]bool{}
	for _, s := range p.Service {
		if !rePromise.MatchString(s) || seen[s] {
			return fmt.Errorf("privacy.service %q is not valid or repeated", s)
		}
		seen[s] = true
	}
	if err := p.Hosting.Validate(); err != nil {
		return fmt.Errorf("privacy.hosting: %v", err)
	}
	return nil
}

// Validate checks that the hosting statement is complete and consistent.
func (h *Hosting) Validate() error {
	if h.Provider != "" && (!validText(h.Provider, 64) || strings.ContainsAny(h.Provider, "\n\t")) {
		return errors.New("provider is not valid")
	}
	if !h.Declared {
		if h.Provider != "" || h.AccessLogs != nil || h.RetentionDays != nil || h.Fields != nil || h.QueryBodyLogged != nil {
			return errors.New("an undeclared hosting statement has no other fields")
		}
		return nil
	}
	if h.AccessLogs == nil || h.QueryBodyLogged == nil {
		return errors.New("a declared hosting statement needs access_logs and query_body_logged")
	}
	if !*h.AccessLogs {
		if h.RetentionDays != nil || h.Fields != nil {
			return errors.New("retention_days and fields are only for access_logs true")
		}
		if *h.QueryBodyLogged {
			return errors.New("query_body_logged true needs access_logs true")
		}
		return nil
	}
	if h.RetentionDays == nil || *h.RetentionDays < 0 || *h.RetentionDays > MaxRetentionDays {
		return fmt.Errorf("access_logs true needs retention_days between 0 and %d", MaxRetentionDays)
	}
	if len(h.Fields) == 0 {
		return errors.New("access_logs true needs the list of fields")
	}
	seen := map[string]bool{}
	for _, f := range h.Fields {
		if !slices.Contains(AccessLogFields, f) || seen[f] {
			return fmt.Errorf("field %q is not known or repeated", f)
		}
		seen[f] = true
	}
	return nil
}

// KeepsAddresses tells a client what to show the person about client
// addresses at the hosting layer: known is false when the operator did
// not declare it (assume they may be kept), otherwise keeps says whether
// the access log holds the address and days for how long.
func (h Hosting) KeepsAddresses() (known, keeps bool, days int) {
	if !h.Declared || h.AccessLogs == nil {
		return false, true, 0
	}
	if !*h.AccessLogs || !slices.Contains(h.Fields, "ip") {
		return true, false, 0
	}
	if h.RetentionDays != nil {
		days = *h.RetentionDays
	}
	return true, true, days
}

// LogsQueryBody tells whether the hosting layer may keep request bodies,
// which hold the search query. An undeclared host may.
func (h Hosting) LogsQueryBody() bool {
	return !h.Declared || h.QueryBodyLogged == nil || *h.QueryBodyLogged
}
