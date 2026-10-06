---
id: secure-boot-module-rejected
revision: 1
updated: "2026-10-05"
kind: fix
intents: [diagnose, fix.module]
components: [secure_boot, kernel, akmods, dkms]
errors: ["kernel:key-rejected", "modprobe:key-was-rejected-by-service", "EKEYREJECTED"]
keywords: [Secure Boot, Key was rejected by service, module signing, MOK, mokutil, third party module]
applies_to:
  distros: [basalt, fedora]
  arch: [x86_64, aarch64]
proposals:
  - id: enroll-key
    action: mok.enroll
    params: {certificate: /etc/pki/akmods/certs/public_key.der}
    risk: medium
  - id: reboot
    action: system.reboot
    params: {reason: key-enrollment}
    risk: low
    requires: [enroll-key]
references:
  - title: Linux kernel documentation, kernel module signing
    url: https://docs.kernel.org/admin-guide/module-signing.html
  - title: RPM Fusion, Secure Boot howto
    url: https://rpmfusion.org/Howto/Secure%20Boot
title: A kernel module fails to load with "Key was rejected by service"
summary: With Secure Boot on, the kernel loads only modules signed by a key the firmware trusts. A module built on your machine (akmods or DKMS) is signed with a local key that you enroll once.
proposal_text:
  enroll-key: Prepare the enrollment of the akmods signing key of this machine, protected by a one time password you choose.
  reboot: Restart, then confirm the key on the blue enrollment screen with the same password.
---
## What it means

`modprobe` prints `Key was rejected by service` (error `EKEYREJECTED`)
when Secure Boot is on and the module is not signed by a key the system
trusts. Modules that come with the kernel are signed by the
distribution; third party modules built on your machine (by akmods or
DKMS, for example a graphics or network driver) are signed with a key
of this machine, which the firmware only trusts after you enroll it as a
machine owner key (MOK).

Turning Secure Boot off is not the fix: it removes a protection against
tampered boot code for every module, not only this one.

## Check

```sh
mokutil --sb-state
modinfo -F signer MODULE
mokutil --list-enrolled | grep -i -A2 subject
```

Replace MODULE with the module name. If the signer is the akmods key of
this machine and that key is not in the enrolled list, enroll it.

## Fix

1. Create the key if it does not exist yet (`/etc/pki/akmods/certs/public_key.der`):
   `sudo kmodgenca -a`, then rebuild the module: `sudo akmods --force`.
2. Ask the firmware to enroll it:

   ```sh
   sudo mokutil --import /etc/pki/akmods/certs/public_key.der
   ```

   Choose a one time password.
3. Restart. On the blue MOK management screen choose Enroll MOK,
   Continue, Yes, type the password, then Reboot.

After the restart, `modprobe MODULE` loads it. DKMS uses its own key
(`/var/lib/dkms/mok.pub`); enroll that file instead when the module comes
from DKMS.
