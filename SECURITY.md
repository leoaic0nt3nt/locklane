# Security model

LOCKLANE is a local network-confinement tool, not an anonymity or account-safety guarantee.

The untrusted workload runs as UID 1000 with all capabilities dropped, no-new-privileges, a read-only image, its own writable home volume and one explicitly selected project mount. It shares only the gateway's network namespace and a read-only status volume. It has no VPN secret or Docker socket.

The trusted root gateway controls networking and can reach the network for VPN bootstrap. UID 1001 probes the exact route available through the VPN, never the root bypass. UID 1000 is allowed to leave only through the chosen tunnel interface and only after the pinned IP check succeeds. Root and the host/Docker administrator are outside the adversarial model. Status writes and application gate updates are atomic.

The primary failure barrier is the kernel's interface-restricted OUTPUT chain, installed before connection. Periodic IP checks and process termination are additional controls. A changing upstream NAT address on a live tunnel can be detected only after the next successful probe; this is a stated limitation. IPv6, private destinations and Docker's DNS shortcut are blocked. Loopback 127.0.0.2, used for the trusted Xray bridge, is not allowed to the workspace.

The web control panel binds IPv4 loopback on an ephemeral port, authenticates all API operations with a random 256-bit token, rejects mismatched Host/Origin, has a self-only CSP and does not transmit telemetry. VPN URLs and credentials must not appear in logs or API responses. Subscription retrieval is HTTPS-only, size-limited, public-IPv4-only (also on redirects), uses no third-party converter and executes no subscription scripts. An imported remote VPN is trusted with traffic routed through it.

Report vulnerabilities privately through the repository's Security Advisories if available, or contact the maintainer without including live credentials. Do not publish keys, real subscriptions or auth volumes.

Before stable release: review NET_ADMIN boundary, signed installers, supply-chain pinning, every supported protocol with a real server, Windows/macOS cold boot, sleep/wake, active TCP-stream drop tests and a separate security review. These are release gates, not already-completed claims.
