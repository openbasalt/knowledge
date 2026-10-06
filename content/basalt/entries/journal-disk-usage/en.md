---
id: journal-disk-usage
revision: 1
updated: "2026-10-05"
kind: fix
intents: [diagnose, fix.disk]
components: [systemd_journald, dnf, disk]
errors: ["ENOSPC", "disk:full"]
keywords: [disk full, No space left on device, journal, journalctl, vacuum, package cache, dnf clean]
applies_to:
  distros: [basalt, fedora]
proposals:
  - id: vacuum-journal
    action: journal.vacuum
    params: {size: 500M}
    risk: medium
  - id: clean-packages
    action: dnf.clean
    risk: low
references:
  - title: journalctl manual page
    url: https://man7.org/linux/man-pages/man1/journalctl.1.html
  - title: journald.conf manual page
    url: https://man7.org/linux/man-pages/man5/journald.conf.5.html
title: The root file system fills up with logs and downloaded packages
summary: The system journal and the package cache can grow to several gigabytes. Shrinking the journal to a fixed size and cleaning downloaded packages gives the space back without touching your files.
proposal_text:
  vacuum-journal: Shrink the system journal to 500 MB by removing its oldest files.
  clean-packages: Remove downloaded package files that are already installed.
---
## Check

```sh
df -h /
journalctl --disk-usage
sudo du -sh /var/cache/libdnf5 /var/cache/dnf 2>/dev/null
```

On btrfs, `df` counts snapshots too: old snapshots hold the space of
files that were deleted or replaced since they were taken. On Basalt OS,
`basalt disk` shows what each snapshot holds alone.

## Fix

Shrink the journal (the oldest entries go first) and clean the package
cache:

```sh
sudo journalctl --vacuum-size=500M
sudo dnf clean packages
```

To keep the journal small for good, set a limit in a drop-in file and
restart journald:

```ini
# /etc/systemd/journald.conf.d/size.conf
[Journal]
SystemMaxUse=500M
```

```sh
sudo systemctl restart systemd-journald
```

Removing the journal's oldest entries cannot be undone, and snapshots do
not bring them back (`/var/log` is not part of a system snapshot).
