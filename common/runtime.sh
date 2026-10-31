#!/usr/bin/env bash
# Собственные idempotent boot hooks. Ни main default, ни глобальные firewall policies не меняются.
set +x
set -Eeuo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1
if [[ ${1:-} != --apply ]]; then
    printf '%s\n' 'DRY-RUN: внутренний runtime hook; запускается подготовленными units только после --apply оператора.'
    exit 0
fi
shift
[[ $EUID == 0 ]] || exit 2
if [[ ${1:-} == restore-transit ]]; then
    [[ ${2:-} == /var/lib/paco-deploy/transactions/*/awg1.runtime.conf ]] || exit 2
    # Нельзя отдавать stderr awg в journal.
    awg syncconf awg1 "$2" >/dev/null 2>&1
    exit
fi
[[ -f /etc/paco-deploy/runtime.env && ! -L /etc/paco-deploy/runtime.env ]] || exit 2
[[ $(stat -c %u /etc/paco-deploy/runtime.env) == 0 && $(stat -c %a /etc/paco-deploy/runtime.env) == 600 ]] || exit 2
# Генерируется комплектом; это НЕ пользовательский config/inventory.
# shellcheck source=/dev/null
source /etc/paco-deploy/runtime.env

undo() {
    [[ -n ${PACO_TX:-} ]] || return 0
    python3 /usr/local/lib/paco-deploy/common/data.py record-command "$PACO_TX" "$@"
}

ensure_rule() {
    local tool=$1 table=$2 chain=$3; shift 3
    if ! "$tool" -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null; then
        undo "$tool" -w 5 -t "$table" -D "$chain" "$@"
        "$tool" -w 5 -t "$table" -I "$chain" 1 "$@"
    fi
}

guard() {
    # rule/unreachable не зависят от существования awg0/awg1.
    if [[ $ROLE == entry ]]; then
        if ! ip -4 rule show | grep -Eq "^100:.*from $CLIENT_CIDR lookup 100$"; then
            undo ip -4 rule del pref 100 from "$CLIENT_CIDR" table 100
            ip -4 rule add pref 100 from "$CLIENT_CIDR" table 100
        fi
        local transit=${ENTRY_AWG1_ADDR%/*}
        if ! ip -4 rule show | grep -Eq "^99:.*from $transit lookup 100$"; then
            undo ip -4 rule del pref 99 from "$transit/32" table 100
            ip -4 rule add pref 99 from "$transit/32" table 100
        fi
        # Не регистрируем удаление fallback: при любом rollback защитный маршрут остаётся.
        ip -4 route replace unreachable default table 100 metric 4278198272
        ensure_rule iptables filter FORWARD -i awg1 -o awg0 -d "$CLIENT_CIDR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        ensure_rule iptables filter FORWARD -i awg0 -o awg1 -s "$CLIENT_CIDR" -j ACCEPT
        ensure_rule iptables filter FORWARD -i awg0 '!' -s "$CLIENT_CIDR" -j DROP
        ensure_rule iptables filter FORWARD -i awg0 -s "$CLIENT_CIDR" '!' -o awg1 -j DROP
        # Независимо от источника: spoofed packet с awg0 также не уходит на WAN.
        ensure_rule iptables filter FORWARD -i awg0 '!' -o awg1 -j DROP
        ensure_rule ip6tables filter FORWARD -i awg0 -j DROP
        ensure_rule ip6tables filter FORWARD -o awg0 -j DROP
        ensure_rule ip6tables filter INPUT -i awg0 -j DROP
        # Клиентские пакеты не должны обращаться к локальному SSH/сервисам ENTRY.
        ensure_rule iptables filter INPUT -i awg0 -j DROP
        ensure_rule iptables filter INPUT -p udp --dport "$CLIENT_PORT" -j ACCEPT
        # Если чужой ACCEPT оказался выше уже существовавшей защиты, не разрешать
        # запуск AWG0. Автоматически переставлять чужие правила небезопасно.
        local first
        first=$(iptables -S FORWARD | awk '/^-A / {print; exit}')
        [[ $first == '-A FORWARD -i awg0 ! -o awg1 -j DROP' ]] || return 2
        local top6
        top6=$(ip6tables -S FORWARD | awk '/^-A / {print; if (++n==2) exit}')
        [[ $top6 == $'-A FORWARD -o awg0 -j DROP\n-A FORWARD -i awg0 -j DROP' ]] || return 2
    else
        ensure_rule iptables filter FORWARD -i "$WAN" -o awg1 -d "$CLIENT_CIDR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        ensure_rule iptables filter FORWARD -i awg1 -o "$WAN" -s "$CLIENT_CIDR" -j ACCEPT
        ensure_rule iptables filter FORWARD -i awg1 '!' -s "$CLIENT_CIDR" -j DROP
        ensure_rule iptables filter FORWARD -i awg1 '!' -o "$WAN" -j DROP
        ensure_rule ip6tables filter FORWARD -i awg1 -j DROP
        ensure_rule ip6tables filter FORWARD -o awg1 -j DROP
        ensure_rule iptables nat POSTROUTING -s "$CLIENT_CIDR" -o "$WAN" -j MASQUERADE
    fi
    ensure_rule iptables filter INPUT -p udp -s "$OTHER_IP/32" --dport "$TRANSIT_PORT" -j ACCEPT
    ensure_rule iptables filter INPUT -p udp '!' -s "$OTHER_IP/32" --dport "$TRANSIT_PORT" -j DROP
    # Межсерверный peer — только подтверждённый IPv4. Не оставлять IPv6 UDP обход whitelist.
    ensure_rule ip6tables filter INPUT -p udp --dport "$TRANSIT_PORT" -j DROP
    if [[ $NEW_NODE == YES ]]; then
        ensure_rule iptables filter INPUT -p tcp -s "$SSH_SOURCE_CIDR" --dport "$SSH_PORT" -j ACCEPT
        ensure_rule iptables filter INPUT -p tcp '!' -s "$SSH_SOURCE_CIDR" --dport "$SSH_PORT" -m conntrack --ctstate NEW -j DROP
    fi
}

case "${1:-}" in
    guard) guard;;
    route-up)
        if [[ $ROLE == entry ]]; then
            # Loose reverse-path validation для ответов Internet -> awg1.
            sysctl -w net.ipv4.conf.awg1.rp_filter=2 >/dev/null
            ip -4 route replace default dev awg1 table 100 metric 0
        else
            ip -4 route replace "$CLIENT_CIDR" dev awg1
        fi;;
    route-down)
        if [[ $ROLE == entry ]]; then
            ip -4 route del default dev awg1 table 100 metric 0 2>/dev/null || true
            ip -4 route replace unreachable default table 100 metric 4278198272
        else
            ip -4 route del "$CLIENT_CIDR" dev awg1 2>/dev/null || true
        fi;;
    *) exit 2;;
esac
