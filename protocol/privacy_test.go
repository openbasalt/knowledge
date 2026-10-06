package protocol

import "testing"

func ptr[T any](v T) *T { return &v }

func TestHostingValidate(t *testing.T) {
	logs := []string{"ip", "time", "method", "path", "status", "size"}
	good := map[string]Hosting{
		"undeclared": {},
		"access logs": {Declared: true, Provider: "Quave ONE", AccessLogs: ptr(true), RetentionDays: ptr(30),
			Fields: logs, QueryBodyLogged: ptr(false)},
		"no access logs": {Declared: true, AccessLogs: ptr(false), QueryBodyLogged: ptr(false)},
	}
	for name, h := range good {
		if err := h.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]Hosting{
		"undeclared with facts":      {AccessLogs: ptr(false)},
		"undeclared with provider":   {Provider: "x"},
		"declared without logs flag": {Declared: true, QueryBodyLogged: ptr(false)},
		"declared without body flag": {Declared: true, AccessLogs: ptr(false)},
		"logs without retention":     {Declared: true, AccessLogs: ptr(true), Fields: logs, QueryBodyLogged: ptr(false)},
		"logs without fields":        {Declared: true, AccessLogs: ptr(true), RetentionDays: ptr(30), QueryBodyLogged: ptr(false)},
		"unknown field":              {Declared: true, AccessLogs: ptr(true), RetentionDays: ptr(30), Fields: []string{"cookie"}, QueryBodyLogged: ptr(false)},
		"repeated field":             {Declared: true, AccessLogs: ptr(true), RetentionDays: ptr(30), Fields: []string{"ip", "ip"}, QueryBodyLogged: ptr(false)},
		"negative retention":         {Declared: true, AccessLogs: ptr(true), RetentionDays: ptr(-1), Fields: logs, QueryBodyLogged: ptr(false)},
		"no logs but retention":      {Declared: true, AccessLogs: ptr(false), RetentionDays: ptr(30), QueryBodyLogged: ptr(false)},
		"no logs but body logged":    {Declared: true, AccessLogs: ptr(false), QueryBodyLogged: ptr(true)},
		"provider with newline":      {Declared: true, Provider: "a\nb", AccessLogs: ptr(false), QueryBodyLogged: ptr(false)},
	}
	for name, h := range bad {
		if err := h.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := Privacy{Service: []string{PromiseNoAccounts, PromiseNoAccounts}}
	if err := p.Validate(); err == nil {
		t.Error("a repeated service promise was accepted")
	}
}

func TestHostingSummary(t *testing.T) {
	if known, keeps, _ := (Hosting{}).KeepsAddresses(); known || !keeps {
		t.Error("an undeclared host must read as unknown and possibly keeping addresses")
	}
	if !(Hosting{}).LogsQueryBody() {
		t.Error("an undeclared host must read as possibly logging bodies")
	}
	h := Hosting{Declared: true, AccessLogs: ptr(true), RetentionDays: ptr(30),
		Fields: []string{"ip", "time", "path"}, QueryBodyLogged: ptr(false)}
	if known, keeps, days := h.KeepsAddresses(); !known || !keeps || days != 30 {
		t.Errorf("got known=%v keeps=%v days=%d", known, keeps, days)
	}
	if h.LogsQueryBody() {
		t.Error("query_body_logged false read as logged")
	}
	h.Fields = []string{"time", "path"}
	if _, keeps, _ := h.KeepsAddresses(); keeps {
		t.Error("a log without the ip field read as keeping addresses")
	}
	off := Hosting{Declared: true, AccessLogs: ptr(false), QueryBodyLogged: ptr(false)}
	if known, keeps, _ := off.KeepsAddresses(); !known || keeps {
		t.Error("a host without access logs read as keeping addresses")
	}
}
