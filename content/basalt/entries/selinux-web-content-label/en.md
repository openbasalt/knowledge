---
id: selinux-web-content-label
revision: 1
updated: "2026-10-05"
kind: fix
intents: [diagnose, fix.selinux]
components: [selinux, nginx, httpd]
errors: ["http:403", "selinux:avc-denied", "nginx:permission-denied"]
keywords: [403 Forbidden, Permission denied, SELinux, httpd_sys_content_t, restorecon, semanage fcontext, web root, /srv/www]
applies_to:
  distros: [basalt, fedora]
proposals:
  - id: label-web-root
    action: selinux.fcontext
    params: {type: httpd_sys_content_t, path: /srv/www}
    risk: medium
references:
  - title: Fedora documentation, getting started with SELinux
    url: https://docs.fedoraproject.org/en-US/quick-docs/selinux-getting-started/
  - title: semanage-fcontext manual page
    url: https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html
title: Web server answers 403 or "Permission denied" for files in a new directory
summary: nginx and httpd may only read files labeled as web content. Files in a new directory (for example /srv/www) or moved from a home directory keep a label the web server cannot read; a file context rule plus a relabel fixes it.
proposal_text:
  label-web-root: Add a lasting SELinux rule that labels /srv/www as web content, and relabel the files there.
---
## What it means

On an SELinux system the web server runs in the `httpd_t` domain (nginx
too) and may read files labeled `httpd_sys_content_t`. A directory you
create outside `/var/www`, or files moved (not copied) from your home
directory, keep another label (`default_t`, `var_t` or `user_home_t`), so
the server gets "Permission denied" even when the file permissions are
right, and visitors see 403 Forbidden.

## Check

```sh
ls -Z /srv/www
sudo ausearch -m avc -ts recent -c nginx
matchpathcon /srv/www
```

A denial with `scontext=system_u:system_r:httpd_t:s0` and `tcontext=unconfined_u:object_r:default_t:s0` (or
`user_home_t`) on your files confirms it.

## Fix

Label the directory as web content for good, then relabel what is there:

```sh
sudo semanage fcontext -a -t httpd_sys_content_t '/srv/www(/.*)?'
sudo restorecon -Rv /srv/www
```

Use your own directory in place of `/srv/www`. Do not use `chcon` (a
relabel undoes it) and do not switch SELinux to permissive: both hide
the problem instead of fixing it. If the server must also write there
(uploads), the type is `httpd_sys_rw_content_t`, only for the directory
that needs it.
