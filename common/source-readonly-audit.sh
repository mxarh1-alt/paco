#!/usr/bin/env bash
# PACO: read-only diagnostics of one Linux node. No secret config content is printed.
set -uo pipefail
role="${1:-}"
if [[ "$role" != "entry" && "$role" != "exit" ]]; then
  echo "Usage: sudo bash 04_paco_readonly_audit.sh entry|exit" >&2
  exit 2
fi
printf '%s\n' '=== PACO READ-ONLY AUDIT ==='
printf 'Role: %s\nHost: %s\n' "$role" "$(hostname)"
if [[ -r /etc/os-release ]]; then
  ( . /etc/os-release; printf 'OS: %s\n' "${PRETTY_NAME:-unknown}" )
fi
printf 'Kernel: %s\n' "$(uname -r)"
for cmd in awg awg-quick ip iptables nft ufw; do
  if command -v "$cmd" >/dev/null 2>&1; then printf '%s: installed\n' "$cmd"; else printf '%s: absent\n' "$cmd"; fi
done
printf '\n=== NETWORK INTERFACES (addresses are not secrets, but review before sharing) ===\n'
if command -v ip >/dev/null 2>&1; then ip -br -4 address || true; fi
printf '\n=== WAN DEFAULT ROUTE ===\n'
if command -v ip >/dev/null 2>&1; then ip -4 route show default || true; fi
printf '\n=== FORWARDING ===\n'
sysctl net.ipv4.ip_forward 2>/dev/null || true
printf '\n=== AWG PEER COUNTS ONLY ===\n'
for intf in awg0 awg1; do
  if command -v awg >/dev/null 2>&1 && awg show "$intf" peers >/dev/null 2>&1; then
    count=$(awg show "$intf" peers | awk 'END {print NR+0}')
    printf '%s running peer count: %s\n' "$intf" "$count"
  else printf '%s not found/running\n' "$intf"; fi
  cfg="/etc/amnezia/${intf}.conf"
  if [[ -r "$cfg" ]]; then
    count=$(awk '/^[[:space:]]*\[Peer\][[:space:]]*$/ {n++} END {print n+0}' "$cfg")
    printf '%s config peer count: %s\n' "$intf" "$count"
  fi
done
printf '\n=== SYSTEMD ===\n'
if command -v systemctl >/dev/null 2>&1; then
  for unit in paco-failclosed.service awg-quick@awg0.service awg-quick@awg1.service netfilter-persistent.service ufw.service paco-awg-traffic.timer; do
    printf '%-38s enabled=%-10s active=%s\n' "$unit" \
      "$(systemctl is-enabled "$unit" 2>/dev/null || true)" \
      "$(systemctl is-active "$unit" 2>/dev/null || true)"
  done
fi
if [[ "$role" == "entry" ]]; then
  printf '\n=== ENTRY POLICY AND FAIL-CLOSED ===\n'
  if command -v ip >/dev/null 2>&1; then
    ip -4 rule show || true
    if ! ip -4 route show table 100 2>/dev/null; then
      echo 'Policy table 100: not configured yet'
    fi
    if ip link show awg0 >/dev/null 2>&1; then
      ip -4 route get 1.1.1.1 from 10.77.77.2 iif awg0 2>&1 || true
    fi
  fi
  if command -v iptables >/dev/null 2>&1; then
    if iptables -C FORWARD -i awg0 -s 10.77.77.0/24 ! -o awg1 -j DROP 2>/dev/null; then
      echo 'AWG0 fail-closed FORWARD: PRESENT'
    else echo 'AWG0 fail-closed FORWARD: NOT CONFIRMED'; fi
  fi
else
  printf '\n=== EXIT RETURN ROUTE / NAT / UFW ===\n'
  if command -v ip >/dev/null 2>&1; then ip -4 route show 10.77.77.0/24 || true; fi
  if command -v iptables >/dev/null 2>&1; then
    iptables -t nat -S POSTROUTING 2>/dev/null | grep -- '10.77.77.0/24' || echo 'No matching legacy PACO NAT rule observed'
  fi
  if command -v ufw >/dev/null 2>&1; then ufw status 2>/dev/null | head -25 || true; fi
fi
printf '\nAUDIT FINISHED. No settings changed. Review IPs/hostnames before sharing output.\n'
