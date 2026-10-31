#!/usr/bin/env bash
set +x
set -Eeuo pipefail
export PYTHONDONTWRITEBYTECODE=1
ACTION=${1:?action required}
shift
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
parse_args "$@"

plan() {
    case "$ACTION" in
        install-awg) note 'ПЛАН: только новый Ubuntu 24.04 amd64: официальный PPA через add-apt-repository, APT подписи, точные версии пакетов, без reboot/full-upgrade.';;
        keys) note 'ПЛАН: только локальное создание transit private/public key на проверенном VPS; наружу выводится лишь public key. Сеть не меняется.';;
        A-prepare-exit|B-setup-exit) note 'ПЛАН: новый EXIT; backup, постоянный rollback timer, модульный probe, явный AWG1, ограниченный firewall/NAT, return route, sysctl forwarding, systemd. Старый EXIT не меняется.';;
        A-switch-entry) note 'ПЛАН: действующая ENTRY; backup AWG1+peer manifest, rollback timer, независимая failclosed/IPv6 защита, allowlist нового EXIT, атомарная запись AWG1 и ограниченный syncconf. AWG0/менеджер не перезапускаются и не изменяются.';;
        B-setup-entry) note 'ПЛАН: новый ENTRY; backup+timer, независимый guard до AWG0/AWG1, AWG1 transit. AWG0 пока не запускается.';;
        B-clients) note 'ПЛАН: только ENTRY B; локальный импорт исходных идентичностей либо новый peer/приватный профиль; проверить kernel parser на probe, оставить все клиентские ключи при rollback. Менеджер — только offline quarantine.';;
        B-connect) note 'ПЛАН: read-only transit handshake+ping; изменения не выполняются.';;
        A-commit|B-commit) note 'ПЛАН: read-only функциональные проверки и свежая операторская acceptance; только затем снять timer данной транзакции. Проверять на ОБОИХ узлах.';;
        preflight) note 'ПЛАН: только read-only проверки локального VPS.';;
        backup) note 'ПЛАН: защищённый timestamp backup; SQLite backup API/integrity_check; никаких сетевых изменений.';;
        verify) note 'ПЛАН: только read-only policy/firewall/NAT/handshake/ping проверки.';;
        rollback) note 'ПЛАН: обратные только собственные действия указанной active транзакции; старый AWG1 syncconf; AWG0 данные не удаляются; main default и глобальный firewall не восстанавливаются вслепую.';;
        failclosed-drill) note 'ПЛАН: только ENTRY в окне обслуживания; временная потеря route или stop AWG1, предварительная страховка восстановления через 45 секунд, проверка unreachable и независимого DROP, немедленное восстановление. Реальные утечки отдельно наблюдать с клиента.';;
        *) die 'Неизвестный этап';;
    esac
}
plan
# Emergency rollback не зависит от исправности AWG, inventory или IPv6 evidence.
# Он может только вернуть уже одобренную active транзакцию на этом узле.
if [[ $ACTION == rollback ]]; then
    [[ $SNAPSHOT =~ ^[0-9]{8}T[0-9]{6}-[a-f0-9-]{36}$ ]] || die 'Нужен --snapshot ID из ROLLBACK ARMED'
    if ((!APPLY)); then note 'DRY-RUN: rollback не выполняется; config/inventory для аварийного отката не нужны'; exit 0; fi
    ((EUID==0)) || die 'Rollback требует root'
    [[ $CONFIRM == 'APPLY rollback' ]] || die "Нужно --confirm 'APPLY rollback'"
    [[ -f $STATE/active && $(cat "$STATE/active") == "$SNAPSHOT" ]] || die 'Этот snapshot не является active на данном узле'
    exec "$RUNTIME/common/rollback-runtime.sh" --apply "$SNAPSHOT"
fi
load_config

check_target() {
    case "$ACTION" in
        A-*) [[ $SCENARIO == A ]] || die 'Это не inventory A';;
        B-*) [[ $SCENARIO == B ]] || die 'Это не inventory B';;
    esac
    case "$ACTION" in
        *prepare-exit|*setup-exit) [[ $ROLE == exit ]] || die 'Этап только на EXIT';;
        *switch-entry|*setup-entry|B-clients|B-connect|failclosed-drill) [[ $ROLE == entry ]] || die 'Этап только на ENTRY';;
    esac
}
check_target

preflight() {
    local action=${1:-$ACTION}
    local tool
    for tool in python3 ip systemctl hostname dpkg; do need "$tool"; done
    if [[ $action != install-awg ]]; then
        for tool in iptables ip6tables iptables-save ip6tables-save nft awg awg-quick modinfo ping ss tar flock systemd-analyze; do need "$tool"; done
    fi
    python3 "$KIT/common/checks.py" preflight "$CONFIG" "$INVENTORY" "$action"
}

require_peer_keys() {
    [[ ${ENTRY_TRANSIT_PUBLIC_KEY:-TO_FILL} != TO_* && ${EXIT_TRANSIT_PUBLIC_KEY:-TO_FILL} != TO_* ]] || die 'Сначала локальные keys на обоих узлах и обмен ТОЛЬКО public keys'
}

make_key() {
    local name=$1
    if [[ ! -f $STATE/keys/$name.key ]]; then
        local tmp
        tmp=$(mktemp "$STATE/keys/.key.XXXXXXXX")
        awg genkey > "$tmp"
        chmod 0600 "$tmp"
        mv -T -- "$tmp" "$STATE/keys/$name.key"
    fi
    secure_local "$STATE/keys/$name.key"
    awg pubkey 2>/dev/null < "$STATE/keys/$name.key" > "$STATE/keys/$name.pub"
    chmod 0600 "$STATE/keys/$name.pub"
}

probe_config() {
    local conf=$1 probe=pacoprobe
    if ip link show "$probe" >/dev/null 2>&1; then die 'Имя pacoprobe занято; не удаляется автоматически'; fi
    quiet modprobe amneziawg
    python3 "$KIT/common/data.py" probe-config "$conf" "$STATE/stage/probe.conf"
    quiet ip link add "$probe" type amneziawg
    # EXIT trap удаляет только интерфейс, созданный этой функцией; никогда awg0/awg1.
    trap 'ip link del pacoprobe >/dev/null 2>&1 || true' EXIT
    quiet awg setconf "$probe" "$STATE/stage/probe.conf"
    awg showconf "$probe" > "$STATE/stage/probe-result.conf" 2>/dev/null
    python3 "$KIT/common/data.py" probe-result "$conf" "$STATE/stage/probe-result.conf"
    ip link del "$probe"
    trap - EXIT
    rm -f -- "$STATE/stage/probe.conf" "$STATE/stage/probe-result.conf"
}

install_runtime() {
    install -d -m 0700 /etc/paco-deploy
    {
        printf 'ROLE=%q\nWAN=%q\nOTHER_IP=%q\n' "$ROLE" "$WAN" "$OTHER_IP"
        printf 'CLIENT_CIDR=%q\nENTRY_AWG1_ADDR=%q\n' "$CLIENT_CIDR" "$ENTRY_AWG1_ADDR"
        printf 'CLIENT_PORT=%q\nTRANSIT_PORT=%q\nSSH_PORT=%q\nSSH_SOURCE_CIDR=%q\n' "$CLIENT_PORT" "$TRANSIT_PORT" "$SSH_PORT" "$SSH_SOURCE_CIDR"
        if [[ $SCENARIO == A && $ROLE == entry ]]; then printf 'NEW_NODE=NO\n'; else printf 'NEW_NODE=YES\n'; fi
    } > "$STATE/stage/runtime.env"
    put_file "$STATE/stage/runtime.env" /etc/paco-deploy/runtime.env
    local legacy=''
    [[ $SCENARIO != A || $ROLE != entry ]] || legacy='paco-failclosed.service'
    write_file /etc/systemd/system/paco-deploy-guard.service <<EOF
[Unit]
Description=PACO independent fail-closed policy and firewall
DefaultDependencies=no
Wants=network-pre.target
After=local-fs.target netfilter-persistent.service $legacy
Before=network-pre.target paco-awg0.service paco-awg1.service awg-quick@awg0.service awg-quick@awg1.service
[Service]
Type=oneshot
RemainAfterExit=yes
UMask=0077
ExecStart=$RUNTIME/common/runtime.sh --apply guard
# Нет ExecStop: guard не исчезает при остановке AWG1 или unit.
[Install]
WantedBy=multi-user.target
EOF
    if [[ $ROLE == entry && $SCENARIO == A ]]; then
        local u
        for u in awg-quick@awg0 awg-quick@awg1; do
            write_file "/etc/systemd/system/$u.service.d/90-paco-guard.conf" <<EOF
[Unit]
Requires=paco-deploy-guard.service
After=paco-deploy-guard.service
EOF
        done
        write_file /etc/systemd/system/awg-quick@awg1.service.d/91-paco-route.conf <<EOF
[Service]
ExecStartPost=$RUNTIME/common/runtime.sh --apply route-up
ExecStopPost=$RUNTIME/common/runtime.sh --apply route-down
EOF
    fi
    write_file /etc/sysctl.d/90-paco-forward.conf <<EOF
net.ipv4.ip_forward=1
-net.ipv4.conf.awg1.rp_filter=2
EOF
    local prior
    prior=$(sysctl -n net.ipv4.ip_forward)
    if [[ $prior != 1 ]]; then record_undo sysctl -w "net.ipv4.ip_forward=$prior"; sysctl -w net.ipv4.ip_forward=1 >/dev/null; fi
    PACO_TX=$TX "$RUNTIME/common/runtime.sh" --apply guard
    systemd-analyze verify /etc/systemd/system/paco-deploy-guard.service >/dev/null 2>&1 || die 'Guard unit/dependencies не прошли verify'
    systemctl daemon-reload
    unit_enable paco-deploy-guard.service
    if [[ $SCENARIO == A && $ROLE == entry ]]; then
        # Requires на активном AWG0: stopping guard при rollback мог бы остановить
        # клиентов. В A никогда не записывать такой обратный systemctl stop.
        systemctl start paco-deploy-guard.service
    else
        unit_start paco-deploy-guard.service
    fi
}

install_awg_unit() {
    local intf=$1
    write_file "/etc/systemd/system/paco-$intf.service" <<EOF
[Unit]
Description=PACO explicit-path $intf
Requires=paco-deploy-guard.service
After=network-online.target paco-deploy-guard.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
UMask=0077
TimeoutStartSec=30s
TimeoutStopSec=30s
ExecStart=/usr/bin/awg-quick up /etc/amnezia/$intf.conf
ExecStop=/usr/bin/awg-quick down /etc/amnezia/$intf.conf
StandardOutput=null
StandardError=null
EOF
    if [[ $intf == awg1 ]]; then
        write_file /etc/systemd/system/paco-awg1.service.d/90-route.conf <<EOF
[Service]
ExecStartPost=$RUNTIME/common/runtime.sh --apply route-up
ExecStopPost=$RUNTIME/common/runtime.sh --apply route-down
EOF
    fi
    systemd-analyze verify "/etc/systemd/system/paco-$intf.service" >/dev/null 2>&1 || die 'AWG unit не прошёл verify'
    systemctl daemon-reload
    unit_enable "paco-$intf.service"
    unit_start "paco-$intf.service"
}

setup_node() {
    require_peer_keys
    [[ -f $STATE/keys/transit.key ]] || die 'Сначала common/generate-transit-identity.sh'
    local mine
    mine=$(awg pubkey 2>/dev/null < "$STATE/keys/transit.key")
    if [[ $ROLE == entry ]]; then [[ $mine == "$ENTRY_TRANSIT_PUBLIC_KEY" ]] || die 'Не совпал ENTRY public key'; else [[ $mine == "$EXIT_TRANSIT_PUBLIC_KEY" ]] || die 'Не совпал EXIT public key'; fi
    python3 "$KIT/common/data.py" transit "$CONFIG" "$INVENTORY" "$STATE/keys/transit.key" "$STATE/stage/awg1.conf"
    probe_config "$STATE/stage/awg1.conf"
    begin_tx
    install_runtime
    install -d -m 0700 /etc/amnezia
    put_file "$STATE/stage/awg1.conf" /etc/amnezia/awg1.conf
    install_awg_unit awg1
    finish_pending
}

switch_entry() {
    require_peer_keys
    [[ $(awg show awg1 public-key) == "$ENTRY_TRANSIT_PUBLIC_KEY" ]] || die 'ENTRY public key не совпал с активным AWG1'
    # Для A ключ копируется только из локального исходного конфига, не генерируется заново.
    python3 - "$KIT/common" "$STATE/stage/existing.key" <<'PY'
import sys
sys.path.insert(0,sys.argv[1])
from data import atomic,parse_awg
atomic(sys.argv[2],parse_awg('/etc/amnezia/awg1.conf')[0][1]['PrivateKey']+'\n')
PY
    python3 "$KIT/common/data.py" transit "$CONFIG" "$INVENTORY" "$STATE/stage/existing.key" "$STATE/stage/awg1.conf" /etc/amnezia/awg1.conf
    probe_config "$STATE/stage/awg1.conf"
    begin_tx
    sha256sum /etc/amnezia/awg0.conf | cut -d ' ' -f1 > "$TX/awg0.sha256"
    python3 "$KIT/common/data.py" fingerprint /etc/amnezia/awg0.conf > "$TX/awg0.manifest"
    awg show awg0 peers | sort | sha256sum | cut -d ' ' -f1 > "$TX/awg0.runtime-peers.sha256"
    sha256sum /usr/local/sbin/paco-awg.py | cut -d ' ' -f1 > "$TX/manager.sha256"
    install_runtime
    put_file "$STATE/stage/awg1.conf" /etc/amnezia/awg1.conf
    local old_mtu
    old_mtu=$(ip -j link show awg1 | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["mtu"])')
    if [[ $old_mtu != "$MTU" ]]; then record_undo ip link set dev awg1 mtu "$old_mtu"; ip link set dev awg1 mtu "$MTU"; fi
    python3 "$KIT/common/data.py" strip /etc/amnezia/awg1.conf "$STATE/stage/awg1.stripped.conf"
    quiet awg syncconf awg1 "$STATE/stage/awg1.stripped.conf"
    local old_rp_filter
    old_rp_filter=$(sysctl -n net.ipv4.conf.awg1.rp_filter)
    if [[ $old_rp_filter != 2 ]]; then record_undo sysctl -w "net.ipv4.conf.awg1.rp_filter=$old_rp_filter"; fi
    "$RUNTIME/common/runtime.sh" --apply route-up
    # Пакет запускает handshake; успех ping проверяется отдельным verify, при отказе timer не снимается.
    ping -c 1 -W 2 -I awg1 "$OTHER_ADDR" >/dev/null 2>&1 || true
    finish_pending
}

restore_manager_offline() {
    [[ $MANAGER_MODE == RESTORE_OFFLINE ]] || return 0
    [[ -n ${RESTORE_MANAGER_DIR:-} && $RESTORE_MANAGER_DIR == /* ]] || die 'Нужен локальный root-only RESTORE_MANAGER_DIR'
    local dest=$STATE/manager-quarantine
    [[ ! -e $dest ]] || die 'Quarantine менеджера уже существует; не перезаписывается'
    local staged
    staged=$(mktemp -d "$STATE/.manager-quarantine.XXXXXXXX")
    secure_local "$RESTORE_MANAGER_DIR/paco-awg.py"
    secure_local "$RESTORE_MANAGER_DIR/traffic.sqlite3"
    install -m 0600 "$RESTORE_MANAGER_DIR/paco-awg.py" "$staged/paco-awg.py"
    python3 "$KIT/common/data.py" sqlite-copy "$RESTORE_MANAGER_DIR/traffic.sqlite3" "$staged/traffic.sqlite3"
    python3 "$KIT/common/data.py" manager-report "$CONFIG" "$INVENTORY" "$staged/paco-awg.py" "$staged/review.json"
    mv -T -- "$staged" "$dest"
    note 'SQLite history и исходник менеджера сохранены offline, не активированы. Нужен отдельный аудит v0.2.4/ENDPOINT/NET/unit ExecStart; автоматическая активация STOP.'
}

clients() {
    [[ $CLIENT_IDENTITY_STRATEGY != UNCHANGED ]] || die 'Выберите restore/reissue'
    if [[ -n $CLIENT_PUBLIC_KEY_FILE ]]; then die 'Этот комплект выдаёт профиль с локально созданным ключом; внешний public-only enrollment не включён'; fi
    begin_tx
    local stage=$STATE/stage/awg0.conf
    if [[ $CLIENT_IDENTITY_STRATEGY == RESTORE_FROM_OWNER_BACKUP ]]; then
        [[ -n ${RESTORE_AWG0_FILE:-} ]] || die 'Нужен локальный RESTORE_AWG0_FILE; секреты в чат не передавать'
        python3 "$KIT/common/data.py" restore-clients "$CONFIG" "$INVENTORY" "$RESTORE_AWG0_FILE" "$stage"
        if [[ -e /etc/amnezia/awg0.conf ]]; then
            python3 "$KIT/common/data.py" compare-identity /etc/amnezia/awg0.conf "$stage" || die 'Импорт не должен заменять существующих клиентов/серверный ключ'
        fi
    else
        [[ -n $NAME ]] || die 'Для REISSUE_ALL укажите --name testpaco'
        if [[ -e /etc/amnezia/awg0.conf ]]; then
            cp -- /etc/amnezia/awg0.conf "$stage"
        else
            make_key client-server
            python3 "$KIT/common/data.py" new-awg0 "$CONFIG" "$INVENTORY" "$STATE/keys/client-server.key" "$stage"
        fi
        python3 "$KIT/common/data.py" enroll "$CONFIG" "$INVENTORY" "$stage" "$NAME" "$STATE/clients"
    fi
    probe_config "$stage"
    # AWG0 identities переживают rollback. Их не заносим в delete/restore undo.
    python3 - "$KIT/common" "$stage" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from data import atomic
atomic('/etc/amnezia/awg0.conf',Path(sys.argv[2]).read_bytes())
PY
    if systemctl is-active --quiet paco-awg0.service; then
        python3 "$KIT/common/data.py" strip /etc/amnezia/awg0.conf "$STATE/stage/awg0.stripped.conf"
        quiet awg syncconf awg0 "$STATE/stage/awg0.stripped.conf"
    else
        install_awg_unit awg0
    fi
    [[ $MANAGER_MODE != RESTORE_OFFLINE || -d $STATE/manager-quarantine ]] || restore_manager_offline
    note "Клиентские профили остаются локально в $STATE/clients (0600); приватные файлы не печатаются. При RESTORE исходные профили остаются у владельца."
    finish_pending
}

transit_test() {
    ping -c 3 -W 2 -I awg1 "$OTHER_ADDR" >/dev/null || die 'Transit ping не прошёл'
    python3 - "$OTHER_IP" <<'PY'
import subprocess,time,os
key=os.environ['EXIT_TRANSIT_PUBLIC_KEY'] if os.environ['NODE_ROLE']=='entry' else os.environ['ENTRY_TRANSIT_PUBLIC_KEY']
p=subprocess.run(['awg','show','awg1','latest-handshakes'],capture_output=True,text=True,check=True)
rows=[x.split() for x in p.stdout.splitlines()]
assert len(rows)==1 and rows[0][0]==key and 0 <= time.time()-int(rows[0][1])<=180
PY
    note 'PASS: свежий transit handshake и ping; полный клиентский выход пока не заявлен'
}

fault_recover() {
    if [[ $FAULT == route ]]; then
        "$RUNTIME/common/runtime.sh" --apply route-up
    else
        systemctl start "$FAULT_AWG_UNIT"
    fi
    systemctl stop "$FAULT_RECOVERY.timer" >/dev/null 2>&1 || true
}

fault_drill() {
    [[ $FAULT == route || $FAULT == awg1 ]] || die 'Укажите --fault route|awg1'
    # Требуется именно новая подготовленная независимая защита.
    systemctl is-active --quiet paco-deploy-guard.service || die 'Сначала нужен активный guard'
    [[ -f $STATE/active ]] || die 'Drill разрешён лишь внутри застрахованной active транзакции'
    take_backup
    FAULT_RECOVERY=paco-fault-recovery-$(cat /proc/sys/kernel/random/uuid)
    if [[ $SCENARIO == A ]]; then FAULT_AWG_UNIT=awg-quick@awg1.service; else FAULT_AWG_UNIT=paco-awg1.service; fi
    if [[ $FAULT == route ]]; then
        systemd-run --quiet --unit="$FAULT_RECOVERY" --on-active=45s --timer-property=AccuracySec=1s "$RUNTIME/common/runtime.sh" --apply route-up
    else
        systemd-run --quiet --unit="$FAULT_RECOVERY" --on-active=45s --timer-property=AccuracySec=1s /usr/bin/systemctl start "$FAULT_AWG_UNIT"
    fi
    systemctl is-active --quiet "$FAULT_RECOVERY.timer" || die 'Не вооружён быстрый fault recovery timer'
    trap fault_recover EXIT
    if [[ $FAULT == route ]]; then
        ip -4 route del default dev awg1 table 100 metric 0
    else
        systemctl stop "$FAULT_AWG_UNIT"
    fi
    python3 - "$CLIENT_CIDR" "$TEST_CLIENT_IP" <<'PY'
import subprocess,sys
p=subprocess.run(['ip','-4','route','get','1.1.1.1','from',sys.argv[2],'iif','awg0'],capture_output=True,text=True)
assert p.returncode != 0 and ('No route to host' in p.stderr or 'Network is unreachable' in p.stderr)
p=subprocess.run(['iptables','-S','FORWARD'],capture_output=True,text=True,check=True)
assert next(x for x in p.stdout.splitlines() if x.startswith('-A '))=='-A FORWARD -i awg0 ! -o awg1 -j DROP'
PY
    note 'Наблюдение 10 секунд: на тестовом клиенте не должно быть выхода ни через ENTRY, ни через native IPv6; смотрите заранее запущенные пробы.'
    sleep 10
    fault_recover
    trap - EXIT
    note 'PASS: согласованный отказ дал unreachable, первый FORWARD DROP сохранён; восстановление выполнено. Это не доказательство отсутствия native IPv6/клиентской утечки.'
}

commit() {
    [[ -f $STATE/active ]] || die 'Нет active транзакции для commit'
    local id
    id=$(cat "$STATE/active")
    [[ $id =~ ^[0-9]{8}T[0-9]{6}-[a-f0-9-]{36}$ ]] || die 'Некорректный transaction id'
    TX=$STATE/transactions/$id
    [[ $(cat "$TX/role") == "$ROLE" && $(cat "$TX/scenario") == "$SCENARIO" ]] || die 'Чужая транзакция'
    python3 "$KIT/common/checks.py" verify "$CONFIG" "$INVENTORY"
    if [[ $SCENARIO == A && $ROLE == entry ]]; then
        [[ $(sha256sum /etc/amnezia/awg0.conf | cut -d ' ' -f1) == "$(cat "$TX/awg0.sha256")" ]] || die 'AWG0 изменён — commit запрещён'
        [[ $(awg show awg0 peers | sort | sha256sum | cut -d ' ' -f1) == "$(cat "$TX/awg0.runtime-peers.sha256")" ]] || die 'Состав runtime peer AWG0 изменился'
        [[ $(sha256sum /usr/local/sbin/paco-awg.py | cut -d ' ' -f1) == "$(cat "$TX/manager.sha256")" ]] || die 'Исходник менеджера изменён; commit запрещён'
        systemctl is-active --quiet paco-awg-traffic.timer || die 'Таймер статистики не активен'
    fi
    [[ -n ${ACCEPTANCE_FILE:-} ]] || die 'Нужен свежий root-only ACCEPTANCE_FILE'
    python3 "$KIT/common/checks.py" evidence "$CONFIG" "$INVENTORY" "$ACCEPTANCE_FILE"
    TIMER=$(cat "$TX/timer")
    # Lock удерживается с authorize: timer не может одновременно выполнить rollback.
    systemctl stop "$TIMER.timer"
    systemctl disable "$TIMER.timer" >/dev/null
    mv "$STATE/active" "$TX/committed"
    printf '%s %s %s COMMIT\n' "$(date -u +%FT%TZ)" "$ACTION" "$ROLE" >> "$STATE/operations.log"
    note "COMMITTED: $id; timer снят только на этом узле. Backup не удалён; старый EXIT сохранять до завершения всей приёмки."
}

if ((!APPLY)); then
    note 'DRY-RUN: запись, генерация ключей, probe interface, firewall, systemd enable/reload, установка пакетов НЕ выполняются.'
    preflight
    case "$ACTION" in
        verify) python3 "$KIT/common/checks.py" verify "$CONFIG" "$INVENTORY";;
        B-connect) transit_test;;
    esac
    note 'Предпросмотр завершён; это не разрешение на production.'
    exit 0
fi
authorize
preflight
case "$ACTION" in
    preflight) note 'Read-only preflight PASS';;
    verify) python3 "$KIT/common/checks.py" verify "$CONFIG" "$INVENTORY";;
    backup) take_backup;;
    keys)
        [[ ! ( $SCENARIO == A && $ROLE == entry ) ]] || die 'В A ключ ENTRY запрещено перевыпускать; используйте awg show awg1 public-key'
        take_backup
        make_key transit
        printf '%s keys %s COMPLETE\n' "$(date -u +%FT%TZ)" "$ROLE" >> "$STATE/operations.log"
        note 'TRANSIT PUBLIC KEY (не private):'
        cat "$STATE/keys/transit.pub";;
    A-prepare-exit|B-setup-exit|B-setup-entry) setup_node;;
    A-switch-entry) switch_entry;;
    B-connect) transit_test;;
    B-clients) clients;;
    A-commit|B-commit) commit;;
    rollback)
        [[ -n $SNAPSHOT && $SNAPSHOT =~ ^[0-9]{8}T[0-9]{6}-[a-f0-9-]{36}$ ]] || die 'Укажите --snapshot ID'
        [[ -f $STATE/active && $(cat "$STATE/active") == "$SNAPSHOT" ]] || die 'Rollback разрешён только для active snapshot'
        # Ручной wrapper освобождает lock; callback захватывает его и повторно проверяет active marker.
        flock -u 9
        "$RUNTIME/common/rollback-runtime.sh" --apply "$SNAPSHOT";;
    failclosed-drill) fault_drill;;
    install-awg)
        # Только новые узлы. Никакого отключения TLS/APT signature/checksum verification.
        export DEBIAN_FRONTEND=noninteractive
        installer_backup_dir=$STATE/backups/$(date -u +%Y%m%dT%H%M%S.%N)-pre-install
        install -d -m 0700 "$installer_backup_dir"
        tar --acls --xattrs --numeric-owner -czf "$installer_backup_dir/apt-before.tar.gz" -C / etc/apt etc/os-release var/lib/dpkg/status
        tar -tzf "$installer_backup_dir/apt-before.tar.gz" >/dev/null
        (cd "$installer_backup_dir" && sha256sum apt-before.tar.gz > SHA256SUMS)
        printf '%s install-awg %s START\n' "$(date -u +%FT%TZ)" "$ROLE" >> "$STATE/operations.log"
        note "BACKUP: $installer_backup_dir; установка пакетов обратным journal не отменяется: нужен snapshot нового VPS"
        MAKEFLAGS="-j$(python3 -c 'import os;print(min(2,os.cpu_count() or 1))')"
        export MAKEFLAGS
        # Не использовать уже настроенные insecure/trusted=yes источники.
        python3 - <<'PY'
from pathlib import Path
import re,sys
paths=[Path('/etc/apt/sources.list')]+list(Path('/etc/apt/sources.list.d').glob('*.list'))+list(Path('/etc/apt/sources.list.d').glob('*.sources'))
for p in paths:
    if p.exists() and re.search(r'trusted\s*=\s*yes|^Trusted:\s*yes|allow-insecure\s*=\s*yes',p.read_text(),re.I|re.M):
        sys.exit('NO-GO: найден небезопасный APT source; автоматическая установка запрещена')
PY
        apt_safe() {
            apt-get -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true \
                -o APT::Get::AllowUnauthenticated=false -o Acquire::AllowInsecureRepositories=false \
                -o Acquire::AllowDowngradeToInsecureRepositories=false -o APT::Update::Error-Mode=any "$@"
        }
        apt_safe update
        apt_safe install -y --no-install-recommends software-properties-common python3-launchpadlib gnupg ca-certificates iptables nftables kmod iproute2 iputils-ping sqlite3 "linux-headers-$(uname -r)"
        add-apt-repository --yes --no-update ppa:amnezia/ppa
        apt_safe update
        apt_safe install -y --no-install-recommends \
            'amneziawg=1.0.20210914-0~202608130144+ee0f0a9~ubuntu24.04.1' \
            'amneziawg-tools=1.0.20210914-0~202608130144+ee0f0a9~ubuntu24.04.1' \
            'amneziawg-dkms=1.0.0-0~202609061402+4569c4c~ubuntu24.04.1'
        preflight keys
        printf '%s install-awg %s COMPLETE\n' "$(date -u +%FT%TZ)" "$ROLE" >> "$STATE/operations.log"
        note 'Пакеты установлены. Если DKMS/secure boot не подтвердились, дальнейшее применение NO-GO. Reboot не выполнялся.';;
esac
