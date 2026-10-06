---
id: nvidia-which-driver
revision: 1
updated: "2026-10-05"
kind: reference
intents: [driver.install, driver.choose]
components: [nvidia, nouveau]
keywords: [NVIDIA, GeForce, RTX, GTX, Quadro, nouveau, which driver, open kernel modules]
applies_to:
  distros: [basalt, fedora]
  hardware:
    - bus: pci
      vendor: "10de"
references:
  - title: NVIDIA open GPU kernel modules
    url: https://github.com/NVIDIA/open-gpu-kernel-modules
  - title: RPM Fusion, NVIDIA howto
    url: https://rpmfusion.org/Howto/NVIDIA
title: Which NVIDIA driver fits your GPU
summary: Turing and newer GPUs use the current NVIDIA driver; Maxwell, Pascal and Volta GPUs need the 580 legacy driver; older GPUs stay on the open source nouveau driver.
---
Find your GPU and its id:

```sh
lspci -nn -d 10de:
```

| GPU generation | Examples | Driver |
|---|---|---|
| Turing and newer | GeForce GTX 16, RTX 20, 30, 40 and 50 series | Current NVIDIA driver with the open kernel modules |
| Maxwell, Pascal, Volta | GeForce GTX 750, GTX 900 series, GTX 10 series, Titan V | NVIDIA 580 legacy driver (a separate guide) |
| Kepler and older | GeForce GTX 600 and most GTX 700 | nouveau (no maintained NVIDIA driver) |

The nouveau driver ships with the system and works without any setup:
it drives the display on every generation, with lower 3D performance and
no CUDA.

The NVIDIA drivers are not free software and come from a separate
repository. Installing one replaces nouveau, needs a restart, and on
older GPUs builds a kernel module on your machine. Take a snapshot first
so you can go back.
