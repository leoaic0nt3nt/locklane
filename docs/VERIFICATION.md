# Verification / 18 November 2026

Runtime proof: [CI workflow and public runs](https://github.com/leoaic0nt3nt/locklane/actions/workflows/ci.yml). The initial beta was tested in the private development repository before publication.

- Go tests passed on actual macOS, Windows and Ubuntu runners.
- Real upstream Xray / sing-box binaries accepted ten generated protocol/transport fixtures.
- Fifteen integration checks passed on an isolated Linux Docker engine with synthetic WireGuard and Shadowsocks servers. They include positive routes, exact IP verification, the actual Claude Code `--version` without account login, least privilege, blocked private networks/Docker DNS/IPv6/direct-interface attempts, an existing TCP stream after tunnel removal, a restored ordinary route, wrong pinned IP, locked IP discovery, the private SOCKS bridge, and proxy TUN removal.
- The real local HTTP backend passed token/Origin enforcement, redacted import, separate secret storage, denial of launch/pin without a verified gateway and single-panel reopening.
- The redesigned UI was rendered at 1280×800 and 390×844. Home contains no visible setup inputs. Settings tabs, Escape and first-launch setup were exercised in Chromium without JS errors. Additional **UI-only fixtures** checked saving, discovery, pinning, IP refresh, launcher visibility, wrong IP and stale status. UI fixtures are not VPN/network proof.
- Four architecture-specific archives are built: macOS arm64 / amd64, Windows arm64 / amd64. Local Mac bundles are signed ad hoc and checked with `codesign --verify --deep --strict`. Binary headers are inspected; archives are scanned for local profiles and QA data.

Not claimed: live paid-provider accounts; every transport against a real remote server; real Tailscale account setup in this new container; Windows ARM native installation; native Windows/Mac full cold boot, sleep/wake and network handover; independent security review; Apple notarization / Windows Authenticode. Those remain gates for a stable broad release; see ACCEPTANCE.md. Existing host VPN, LuLu and Claude settings were not modified by product setup/testing.
