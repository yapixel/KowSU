# MKSU

A [KernelSU](https://github.com/tiann/KernelSU)-based root solution for Android devices.

Upstream: [55820e49f2e258426ae635182a89b5a655b6c5d5](https://github.com/tiann/KernelSU/commit/55820e49f2e258426ae635182a89b5a655b6c5d5)

**Experimental. Use at your own risk. (Low frequency maintenance)**

**实验性，风险自负（随缘维护）**

## Features

1. Kernel-based `su` and root access management.
2. Module system not based on [OverlayFS](https://en.wikipedia.org/wiki/OverlayFS).
3. [App Profile](https://kernelsu.org/guide/app-profile.html): Lock up the root power in a cage.

## License

- Files under the `kernel` directory are [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- All other parts except the `kernel` directory are [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

## Credits

- [KernelSU](https://github.com/tiann/KernelSU): The original project.
- [Kernel-Assisted Superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/): The KernelSU idea.
- [Magisk](https://github.com/topjohnwu/Magisk): The powerful root tool.
- [genuine](https://github.com/brevent/genuine/): APK v2 signature validation.
- [Diamorphine](https://github.com/m0nad/Diamorphine): Some rootkit skills.
