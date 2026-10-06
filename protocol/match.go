package protocol

import (
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Facts are what a client knows about the machine (or chose to send in a
// query). An empty field means unknown, never "none".
type Facts struct {
	Distro   string
	Release  string
	Arch     string
	Hardware []HardwareID
	Packages []PackageVersion
}

// FactsOf returns the facts a search request carries.
func FactsOf(r *SearchRequest) Facts {
	return Facts{Distro: r.Distro, Release: r.Release, Arch: r.Arch, Hardware: r.Hardware, Packages: r.Packages}
}

// Outcome of one condition group.
type Outcome int

// Outcomes.
const (
	Unknown Outcome = iota
	Yes
	No
)

// MatchResult says whether conditions hold for some facts. Excluded is
// true when a group the facts speak about fails; Matched lists the groups
// that positively matched (distro, release, arch, hardware, packages).
type MatchResult struct {
	Excluded bool
	Matched  []string
}

// Match evaluates every present condition group against the facts:
//
//   - distros, releases, arch: unknown when the fact is empty, otherwise
//     the fact must be listed (or inside the range);
//   - hardware: unknown when no device is given; matched when any device
//     falls in any range; excluded otherwise (the devices sent are the
//     ones the question is about);
//   - packages: for each listed package, unknown when the facts do not
//     name it, matched or not by version otherwise; the group matches when
//     one package matches and is excluded only when every listed package
//     is named by the facts and none matches.
//
// Matching is the same on the server (search) and on the client (pack
// suggestions from the catalog, computed on the machine).
func (c Conditions) Match(f Facts) MatchResult {
	var res MatchResult
	add := func(name string, o Outcome) {
		switch o {
		case Yes:
			res.Matched = append(res.Matched, name)
		case No:
			res.Excluded = true
		}
	}
	if len(c.Distros) > 0 {
		add("distro", listed(c.Distros, f.Distro))
	}
	if c.Releases != nil {
		add("release", inRange(*c.Releases, f.Release))
	}
	if len(c.Arch) > 0 {
		add("arch", listed(c.Arch, f.Arch))
	}
	if len(c.Hardware) > 0 {
		add("hardware", matchHardware(c.Hardware, f.Hardware))
	}
	if len(c.Packages) > 0 {
		add("packages", matchPackages(c.Packages, f.Packages))
	}
	if res.Excluded {
		res.Matched = nil
	}
	return res
}

func listed(list []string, v string) Outcome {
	if v == "" {
		return Unknown
	}
	if slices.Contains(list, v) {
		return Yes
	}
	return No
}

func inRange(r Range, v string) Outcome {
	if v == "" {
		return Unknown
	}
	if r.Min != "" && CompareVersions(v, r.Min) < 0 {
		return No
	}
	if r.Max != "" && CompareVersions(v, r.Max) > 0 {
		return No
	}
	return Yes
}

func hexVal(s string) (uint64, bool) {
	v, err := strconv.ParseUint(s, 16, 16)
	return v, err == nil
}

// DeviceMatches reports whether one device falls in a hardware match.
func (m HardwareMatch) DeviceMatches(d HardwareID) bool {
	if d.Bus != m.Bus || !strings.EqualFold(d.Vendor, m.Vendor) {
		return false
	}
	if len(m.Devices) == 0 {
		return true
	}
	dv, ok := hexVal(d.Device)
	if !ok {
		return false
	}
	for _, r := range m.Devices {
		lo, ok1 := hexVal(r.From)
		hi, ok2 := hexVal(r.To)
		if ok1 && ok2 && dv >= lo && dv <= hi {
			return true
		}
	}
	return false
}

func matchHardware(ms []HardwareMatch, devs []HardwareID) Outcome {
	if len(devs) == 0 {
		return Unknown
	}
	for _, d := range devs {
		for _, m := range ms {
			if m.DeviceMatches(d) {
				return Yes
			}
		}
	}
	return No
}

func matchPackages(ms []PackageMatch, pkgs []PackageVersion) Outcome {
	if len(pkgs) == 0 {
		return Unknown
	}
	named, failed := 0, 0
	for _, m := range ms {
		for _, p := range pkgs {
			if p.Name != m.Name {
				continue
			}
			named++
			if inRange(Range{Min: m.Min, Max: m.Max}, p.Version) == Yes {
				return Yes
			}
			failed++
			break
		}
	}
	if named == len(ms) && failed == named {
		return No
	}
	return Unknown
}

// CompareVersions compares two version strings the way rpm does
// (rpmvercmp): runs of digits compare as numbers, runs of letters as
// text, a digit run is newer than a letter run, '~' sorts before
// everything (pre-releases) and '^' after the base version (post-release
// snapshots); other separators only split runs. It returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	for a != "" || b != "" {
		a = strings.TrimLeftFunc(a, isSep)
		b = strings.TrimLeftFunc(b, isSep)
		// Tilde: sorts before anything, even the end of the string.
		if strings.HasPrefix(a, "~") || strings.HasPrefix(b, "~") {
			if !strings.HasPrefix(a, "~") {
				return 1
			}
			if !strings.HasPrefix(b, "~") {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		// Caret: sorts after the end of the string, before anything else.
		if strings.HasPrefix(a, "^") || strings.HasPrefix(b, "^") {
			if a == "" {
				return -1
			}
			if b == "" {
				return 1
			}
			if !strings.HasPrefix(a, "^") {
				return 1
			}
			if !strings.HasPrefix(b, "^") {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}
		numeric := unicode.IsDigit(rune(a[0]))
		sa, ra := segment(a, numeric)
		sb, rb := segment(b, numeric)
		if sb == "" {
			// Different kinds: a number is newer than letters.
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			sa = strings.TrimLeft(sa, "0")
			sb = strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				if len(sa) > len(sb) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
		a, b = ra, rb
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	default:
		return 1
	}
}

func isSep(r rune) bool {
	return r != '~' && r != '^' && !unicode.IsDigit(r) && !isLetter(r)
}

func isLetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

func segment(s string, numeric bool) (string, string) {
	i := 0
	for i < len(s) {
		r := rune(s[i])
		if numeric && !unicode.IsDigit(r) || !numeric && !isLetter(r) {
			break
		}
		i++
	}
	return s[:i], s[i:]
}
