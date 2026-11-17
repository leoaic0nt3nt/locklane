#!/bin/bash
set -euo pipefail
mkdir -p /state /var/lib/tailscale
rm -f /state/status.json
# This namespace belongs only to this gateway and its unprivileged workspace.
# Install the drop policy BEFORE starting any VPN or creating a workspace.
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -F OUTPUT
iptables -F INPUT
iptables -N LL_APP 2>/dev/null || true
iptables -F LL_APP
iptables -A LL_APP -j DROP
iptables -A INPUT -i lo -j ACCEPT
# sing-tun hands TCP streams back to a local listener through its TUN.
# The workload still cannot reach the private bridge or send via eth0.
if [ "$LL_PROVIDER" = proxy ]; then iptables -A INPUT -i ll0 -p tcp -j ACCEPT; fi
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Root is the trusted gateway control plane; Claude never runs as root.
iptables -A OUTPUT -m owner --uid-owner 0 -j ACCEPT
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 127.0.0.11/32; do
    iptables -A OUTPUT -d "$net" -j REJECT
done
iptables -A OUTPUT -o lo -d 127.0.0.1/32 -j ACCEPT
IFACE=wg0
if [ "$LL_PROVIDER" = tailscale ]; then IFACE=tailscale0; fi
if [ "$LL_PROVIDER" = proxy ]; then IFACE=ll0; fi
# A separate unprivileged probe can verify the tunnel while Claude is locked.
iptables -A OUTPUT -m owner --uid-owner 1001 -o "$IFACE" -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner 1000 -j LL_APP
# IPv6 is deliberately unavailable in v0.1, including to the control plane.
ip6tables -P OUTPUT DROP
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
exec /usr/local/bin/locklane-gate
