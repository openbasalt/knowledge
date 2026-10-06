package protocol

import (
	"fmt"
	"strings"
)

// ParseHardwareID reads "bus:vendor:device", e.g. "pci:10de:1b81".
func ParseHardwareID(s string) (HardwareID, error) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(s)), ":")
	if len(parts) != 3 {
		return HardwareID{}, fmt.Errorf("hardware id %q: want bus:vendor:device, e.g. pci:10de:1b81", s)
	}
	h := HardwareID{Bus: parts[0], Vendor: parts[1], Device: parts[2]}
	if (h.Bus != "pci" && h.Bus != "usb") || !reHex4.MatchString(h.Vendor) || !reHex4.MatchString(h.Device) {
		return HardwareID{}, fmt.Errorf("hardware id %q: bus pci or usb, four hex digits each", s)
	}
	return h, nil
}

// ParsePackage reads "name=version" or "name".
func ParsePackage(s string) (PackageVersion, error) {
	name, version, _ := strings.Cut(strings.TrimSpace(s), "=")
	p := PackageVersion{Name: name, Version: version}
	if !rePkgName.MatchString(p.Name) || (p.Version != "" && !rePkgVersion.MatchString(p.Version)) {
		return PackageVersion{}, fmt.Errorf("package %q: want name=version", s)
	}
	return p, nil
}
