# Release acceptance

Automated results are recorded by CI. Unchecked items below must remain unchecked until observed on the actual target device.

- [ ] Clean install on macOS Apple silicon and Intel; Gatekeeper behavior recorded.
- [ ] Clean install on Windows x64 and ARM64; Docker Desktop and terminal launch recorded.
- [ ] Choose folder; save; import subscription; no credentials in API, logs or diagnostics.
- [ ] Every advertised transport with a real test server; ordinary/base64 subscriptions; crypto link rejected clearly.
- [ ] IP discovery never permits workload traffic; explicit pin then positive tunnel check.
- [ ] Direct IPv4, IPv6, physical-interface bypass, Docker DNS and private-network access denied.
- [ ] Existing TCP stream cannot continue over direct host route after tunnel deletion.
- [ ] Gateway crash/restart and full Docker engine restart stay closed until verified.
- [ ] Native cold OS boot, log out/in, sleep/wake, network handover.
- [ ] Wrong expected IP, changed upstream NAT, expired Tailscale auth and unavailable exit node.
- [ ] No global DNS/route/firewall/context/autostart mutations; no host Claude, LuLu or other containers modified.
- [ ] Stop retains project and auth data; removal affects only LOCKLANE resources.
- [ ] Separate security review and signed/notarized installers before claiming a stable universal product.

Use neutral destinations and synthetic VPN servers. Do not use real Claude account requests to test leaks. No proof against account bans follows from network tests.
