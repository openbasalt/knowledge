---
id: nvidia-legacy-580
revision: 1
updated: "2026-10-05"
pack: nvidia-legacy-580
kind: guide
intents: [driver.install, driver.legacy]
components: [nvidia, akmods, secure_boot]
errors: ["nvidia:gpu-not-supported", "akmods:build-failed"]
keywords: [GTX 1070, GTX 1080, GTX 1060, GTX 1050, GTX 970, GTX 980, GTX 750, Titan V, Pascal, Maxwell, Volta, NVIDIA 580, akmod, MOK]
applies_to:
  distros: [basalt, fedora]
  hardware:
    - bus: pci
      vendor: "10de"
      devices:
        - {from: "1340", to: "13ff"}
        - {from: "1400", to: "143f"}
        - {from: "15f0", to: "15ff"}
        - {from: "1617", to: "1667"}
        - {from: "17c0", to: "17ff"}
        - {from: "1b00", to: "1bff"}
        - {from: "1c00", to: "1cff"}
        - {from: "1d00", to: "1dff"}
proposals:
  - id: snapshot-before
    action: snapshot.create
    params: {description: before the NVIDIA 580 driver}
    risk: low
  - id: enable-rpmfusion
    action: repo.enable
    params: {repos: "rpmfusion-free rpmfusion-nonfree"}
    risk: medium
    requires: [snapshot-before]
  - id: install-driver
    action: package.install
    params: {packages: "akmod-nvidia-580xx xorg-x11-drv-nvidia-580xx xorg-x11-drv-nvidia-580xx-cuda"}
    risk: high
    requires: [enable-rpmfusion]
  - id: enroll-key
    action: mok.enroll
    params: {certificate: /etc/pki/akmods/certs/public_key.der}
    risk: medium
    requires: [install-driver]
  - id: reboot
    action: system.reboot
    params: {reason: driver-and-key-enrollment}
    risk: low
    requires: [enroll-key]
references:
  - title: NVIDIA Linux driver 580 README, Appendix A (supported GPUs)
    url: https://download.nvidia.com/XFree86/Linux-x86_64/580.178.04/README/supportedchips.html
  - title: RPM Fusion, NVIDIA howto
    url: https://rpmfusion.org/Howto/NVIDIA
  - title: RPM Fusion, Secure Boot howto
    url: https://rpmfusion.org/Howto/Secure%20Boot
title: Install the NVIDIA 580 driver for older GPUs (GTX 10, GTX 900, GTX 750, Titan V)
summary: GPUs of the Maxwell, Pascal and Volta families need the NVIDIA 580 legacy driver. Its kernel module is built on your machine, and with Secure Boot on you enroll a key once, on a firmware screen at the next boot.
proposal_text:
  snapshot-before: Take a snapshot of the system, so you can go back if the new driver causes trouble.
  enable-rpmfusion: Turn on the RPM Fusion free and nonfree repositories, where the driver packages come from.
  install-driver: Install the NVIDIA 580 driver, the tool that builds its kernel module, and nvidia-smi.
  enroll-key: Prepare the enrollment of this machine's module signing key, protected by a one time password you choose.
  reboot: Restart, then confirm the key on the blue enrollment screen with the same password.
---
## Is this guide for your GPU?

Run this in a terminal:

```sh
lspci -nnk -d 10de:
```

Each NVIDIA device shows its id in brackets: `[10de:1b81]` is a GeForce
GTX 1070. This guide is for the Maxwell, Pascal and Volta families:
GeForce GTX 750 and GTX 900 series, GTX 10 series (1050 to 1080 Ti),
Titan X and Titan Xp, Titan V, and the Quadro and Tesla cards of the same
generations. NVIDIA's list of the GPUs the 580 driver supports is the
reference.

GeForce GTX 16, RTX 20 and every newer GPU use the current NVIDIA driver,
not this one. Kepler GPUs (GTX 600 and GTX 700, except the GTX 750) are
not supported by any maintained NVIDIA driver; keep the open source
nouveau driver on them.

## Why this driver is different

NVIDIA's drivers from the 590 series on no longer support these GPUs. The
580 series is the last one that does, and it receives security and
compatibility fixes only, with no new features. NVIDIA lists 580 as a long
term support branch with an end of life in June 2028, and has announced
security updates for GeForce Maxwell, Pascal and Volta GPUs through
October 2028.

The open NVIDIA kernel modules need a Turing or newer GPU, so these cards
use NVIDIA's closed kernel module. It is built on your machine for each
kernel (by akmods), and when Secure Boot is on, the firmware only loads it
after you enroll this machine's signing key (a machine owner key, MOK).

## Before you start

- About 15 minutes, a network connection, and a keyboard at the machine
  for the restart (the enrollment screen needs it).
- Check whether Secure Boot is on: `mokutil --sb-state`.
- Take a snapshot first (the first step below), so you can go back.

## Steps

1. Take a snapshot of the system.

2. Turn on the RPM Fusion repositories (free and nonfree):

   ```sh
   sudo dnf install https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
   ```

3. Install the driver, the module builder and `nvidia-smi`:

   ```sh
   sudo dnf install akmod-nvidia-580xx xorg-x11-drv-nvidia-580xx xorg-x11-drv-nvidia-580xx-cuda
   ```

   `dnf search nvidia-580xx` lists the packages of this branch.

4. With Secure Boot on, enroll the signing key. akmods signs the modules
   it builds with a key of this machine; if `/etc/pki/akmods/certs/public_key.der`
   does not exist yet, `sudo kmodgenca -a` creates it. Then:

   ```sh
   sudo mokutil --import /etc/pki/akmods/certs/public_key.der
   ```

   Choose a one time password and remember it until the restart.

5. Wait for the module to build (a few minutes), then check it:

   ```sh
   modinfo -F version nvidia
   ```

   It prints a 580 version when the module is ready. If it prints
   nothing, run `sudo akmods --force` and read the log it names.

6. Restart. A blue screen (MOK management) appears once: choose Enroll
   MOK, Continue, Yes, type the password, then Reboot. If you miss it, run
   step 4 again and restart.

## Check that it works

```sh
nvidia-smi
lsmod | grep -E '^(nvidia|nouveau)'
mokutil --list-enrolled | grep -i akmods
```

`nvidia-smi` shows your GPU and the 580 driver, `nvidia` is loaded and
`nouveau` is not.

## Kernel updates

Each new kernel needs the module built again; akmods does it on the next
boot, which then takes a little longer. The 580 branch gets kernel
compatibility fixes only from time to time, so a brand new kernel can
arrive before the module builds for it. When that happens, choose the
previous kernel in the boot menu and wait for a driver update.

Sway needs the `--unsupported-gpu` option to start on this driver.

## Going back

Roll back to the snapshot you took, or remove the driver and restart
(nouveau comes back):

```sh
sudo dnf remove '*nvidia-580xx*'
```
