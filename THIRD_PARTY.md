# Third-party software

LOCKLANE's MIT license covers its own orchestration code, interface and scripts. It does not relicense upstream components.

- [sing-box 1.14.4](https://github.com/SagerNet/sing-box/tree/v1.14.4): GPL-3.0-or-later; [license](https://github.com/SagerNet/sing-box/blob/v1.14.4/LICENSE).
- [Xray-core 26.11.9](https://github.com/XTLS/Xray-core/tree/v26.11.9): MPL-2.0; [license](https://github.com/XTLS/Xray-core/blob/v26.11.9/LICENSE).
- [Tailscale](https://github.com/tailscale/tailscale): BSD-3-Clause. Installed from its official stable Debian repository.
- [wireguard-go](https://git.zx2c4.com/wireguard-go/) and [wireguard-tools](https://git.zx2c4.com/wireguard-tools/): upstream licenses apply.
- Debian packages, Node.js, Go, Docker Desktop and Docker Engine retain their own licenses and support requirements.
- Claude Code is obtained by the end user's Docker build from Anthropic's npm package, version 2.1.326. No Claude account, token, native host binary or subscription is distributed with LOCKLANE. Anthropic's terms apply.

The release ZIP contains orchestration binaries and source references, not bundled VPN cores or Claude binaries. The user's build pulls upstream images. If you redistribute built runtime images, include the relevant notices and satisfy corresponding source/license obligations; the source links above identify the core versions used here.

Interface icons: [Lucide](https://github.com/lucide-icons/lucide), ISC license. Settings and refresh paths are sourced from the official icon repository.
