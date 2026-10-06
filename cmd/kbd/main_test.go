package main

import "testing"

func TestHostingFromEnv(t *testing.T) {
	lookup := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	h, err := hostingFromEnv(lookup(nil))
	if err != nil || h.Declared {
		t.Fatalf("unset: %+v %v", h, err)
	}
	h, err = hostingFromEnv(lookup(map[string]string{
		"KBD_HOSTING_ACCESS_LOGS": "true", "KBD_HOSTING_RETENTION_DAYS": "30",
		"KBD_HOSTING_LOG_FIELDS":        "ip, time, method, path, status, size",
		"KBD_HOSTING_QUERY_BODY_LOGGED": "false", "KBD_HOSTING_PROVIDER": "Quave ONE",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if known, keeps, days := h.KeepsAddresses(); !known || !keeps || days != 30 || h.LogsQueryBody() || len(h.Fields) != 6 {
		t.Fatalf("declared: %+v", h)
	}
	h, err = hostingFromEnv(lookup(map[string]string{"KBD_HOSTING_ACCESS_LOGS": "false", "KBD_HOSTING_QUERY_BODY_LOGGED": "false"}))
	if known, keeps, _ := h.KeepsAddresses(); err != nil || !known || keeps {
		t.Fatalf("no logs: %+v %v", h, err)
	}
	for name, m := range map[string]map[string]string{
		"facts without the logs flag": {"KBD_HOSTING_RETENTION_DAYS": "30"},
		"no body flag":                {"KBD_HOSTING_ACCESS_LOGS": "false"},
		"logs without retention":      {"KBD_HOSTING_ACCESS_LOGS": "true", "KBD_HOSTING_LOG_FIELDS": "ip", "KBD_HOSTING_QUERY_BODY_LOGGED": "false"},
		"logs without fields":         {"KBD_HOSTING_ACCESS_LOGS": "true", "KBD_HOSTING_RETENTION_DAYS": "30", "KBD_HOSTING_QUERY_BODY_LOGGED": "false"},
		"unknown field":               {"KBD_HOSTING_ACCESS_LOGS": "true", "KBD_HOSTING_RETENTION_DAYS": "30", "KBD_HOSTING_LOG_FIELDS": "ip,cookie", "KBD_HOSTING_QUERY_BODY_LOGGED": "false"},
		"not a boolean":               {"KBD_HOSTING_ACCESS_LOGS": "yes", "KBD_HOSTING_QUERY_BODY_LOGGED": "false"},
		"days not a number":           {"KBD_HOSTING_ACCESS_LOGS": "true", "KBD_HOSTING_RETENTION_DAYS": "a month", "KBD_HOSTING_LOG_FIELDS": "ip", "KBD_HOSTING_QUERY_BODY_LOGGED": "false"},
	} {
		if _, err := hostingFromEnv(lookup(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
