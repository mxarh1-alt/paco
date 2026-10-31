#!/usr/bin/env bash
# Библиотека; не source inventory и не выводить AWG-конфиги.
set +x
set -Eeuo pipefail
umask 077
KIT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
STATE=/var/lib/paco-deploy
RUNTIME=/usr/local/lib/paco-deploy
CONFIG='' INVENTORY='' CONFIRM='' ACTION=${ACTION:-} APPLY=0
CONSOLE=0 SECOND=0 CUTOVER=0 DRY_SELECTED=0 SNAPSHOT='' NAME='' CLIENT_PUBLIC_KEY_FILE='' FAULT=''
TX='' TIMER='' ROLE='' PREFIX='' WAN='' OTHER_IP='' OTHER_ADDR=''
# Используются вызывающим engine.sh; библиотека также проверяется отдельно.
export SNAPSHOT NAME CLIENT_PUBLIC_KEY_FILE FAULT WAN OTHER_IP OTHER_ADDR

die() { printf 'NO-GO: %s\n' "$*" >&2; exit 2; }
note() { printf '%s\n' "$*"; }
need() { command -v "$1" >/dev/null || die "Нет программы $1"; }

usage() {
    cat <<EOF
PACO: $ACTION
По умолчанию только --dry-run, без записи файлов/изменений системы.
  --config /root/paco/config.env --inventory /root/paco/inventory.env
  --dry-run
  --apply --confirm "APPLY $ACTION" --console-confirmed --second-session-confirmed
  --entry-cutover-approved       отдельное согласие для A/переключения ENTRY
  --snapshot ID                  только ручной rollback
  --name NAME                    имя нового клиента B (REISSUE_ALL)
  --client-public-key-file PATH  публичный ключ, созданный на клиенте
  --fault route|awg1             только tests/failclosed-drill.sh
  --help
Inventory — литеральные значения, не Bash-код. Ключи/PSK сюда не вставлять.
EOF
}

parse_args() {
    while (($#)); do
        case "$1" in
            --config|--inventory|--confirm|--snapshot|--name|--client-public-key-file|--fault)
                (($#>=2)) || die "Нет значения аргумента $1"
                case "$1" in
                    --config) CONFIG=$2;; --inventory) INVENTORY=$2;; --confirm) CONFIRM=$2;;
                    --snapshot) SNAPSHOT=$2;; --name) NAME=$2;;
                    --client-public-key-file) CLIENT_PUBLIC_KEY_FILE=$2;;
                    --fault) FAULT=$2;;
                esac
                shift 2;;
            --apply) ((DRY_SELECTED==0)) || die 'Нельзя одновременно --apply и --dry-run'; APPLY=1; shift;;
            --dry-run) ((APPLY==0)) || die 'Нельзя одновременно --apply и --dry-run'; DRY_SELECTED=1; shift;;
            --console-confirmed) CONSOLE=1; shift;;
            --second-session-confirmed) SECOND=1; shift;;
            --entry-cutover-approved) CUTOVER=1; shift;;
            --help) usage; exit 0;;
            *) die "Неизвестный аргумент $1";;
        esac
    done
}

load_config() {
    [[ -n $CONFIG && -n $INVENTORY && -f $CONFIG && -f $INVENTORY ]] || die 'Укажите существующие --config и --inventory'
    local data k v
    data=$(python3 "$KIT/common/data.py" env "$CONFIG" "$INVENTORY") || exit 2
    while IFS='=' read -r k v; do
        printf -v "$k" '%s' "$v"
        export "${k?}"
    done <<< "$data"
    ROLE=$NODE_ROLE
    PREFIX=${ROLE^^}
    local var
    var=${PREFIX}_WAN_IF; WAN=${!var}
    if [[ $ROLE == entry ]]; then
        OTHER_IP=$EXIT_PUBLIC_IP; OTHER_ADDR=${EXIT_AWG1_ADDR%/*}
    else
        OTHER_IP=$ENTRY_PUBLIC_IP; OTHER_ADDR=${ENTRY_AWG1_ADDR%/*}
    fi
}

secure_local() {
    python3 - "$1" <<'PY'
import os,stat,sys
p=sys.argv[1];s=os.lstat(p)
if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode)&0o077:
    sys.exit('NO-GO: локальный файл должен быть root:root 0600, без symlink')
PY
}

authorize() {
    ((APPLY)) || return 0
    ((EUID==0)) || die '--apply требует root'
    [[ $CONFIRM == "APPLY $ACTION" ]] || die "Подтвердите показанный план: --confirm 'APPLY $ACTION'"
    ((CONSOLE && SECOND)) || die 'Нужны консоль провайдера и вторая проверенная SSH-сессия'
    secure_local "$CONFIG"; secure_local "$INVENTORY"
    [[ $PROVIDER_FIREWALL_VERIFIED == YES && $OFFSITE_BACKUP_VERIFIED == YES ]] || die 'Подтвердите provider firewall и внешнюю копию backup'
    if [[ $ACTION == A-switch-entry ]]; then
        ((CUTOVER)) || die 'Нужно отдельное --entry-cutover-approved'
        [[ $LEGACY_POLICY_AUDITED == YES ]] || die 'Нужно обследовать legacy units/hooks'
    fi
    [[ $CLIENT_IPV6_CAPTURE_VERIFIED == YES ]] || die 'Не подтверждено, что каждый клиент захватывает ::/0 или блокирует свой native IPv6'
    secure_local "$CLIENT_POLICY_EVIDENCE"
    python3 - "$CLIENT_POLICY_EVIDENCE" <<'PY'
import json,sys,time
d=json.load(open(sys.argv[1]))
assert d['all_clients_ipv6_captured_or_os_blocked'] is True
assert d['native_ipv6_test_passed'] is True
assert isinstance(d['reviewed_at_epoch'],int) and 0 <= time.time()-d['reviewed_at_epoch'] <= 86400
assert d['operator'] and d['scope']
PY
    install -d -m 0700 "$STATE" "$STATE/transactions" "$STATE/keys" "$STATE/stage" "$STATE/backups"
    exec 9> /run/lock/paco-deploy.lock
    flock -n 9 || die 'Другая операция PACO уже выполняется'
    if [[ -f $STATE/active && $ACTION != *commit && $ACTION != rollback ]]; then
        if [[ $ACTION != B-clients && $ACTION != failclosed-drill ]]; then
            die 'Есть незавершённая транзакция; сначала verify/commit либо rollback'
        fi
        local active
        active=$(cat "$STATE/active")
        [[ $active =~ ^[0-9]{8}T[0-9]{6}-[a-f0-9-]{36}$ ]] || die 'Некорректная active транзакция'
        if [[ $ACTION == B-clients ]]; then
            [[ $(cat "$STATE/transactions/$active/action") == B-setup-entry ]] || die 'Нельзя продолжать чужую транзакцию'
        fi
    fi
}

quiet() {
    # В том числе ошибки awg не отправлять в journal: они могут включать строку с ключом.
    "$@" >/dev/null 2>&1 || die 'Команда не выполнена; секретные аргументы/вывод скрыты. Таймер отката сохранён.'
}

record_undo() { python3 "$KIT/common/data.py" record-command "$TX" "$@"; }
put_file() { python3 "$KIT/common/data.py" put "$TX" "$1" "$2"; }

write_new_file() {
    local target=$1 tmp
    [[ ! -e $target ]] || die 'Новый идентификатор файла уже занят'
    tmp=$(mktemp "$STATE/stage/new.XXXXXXXX")
    cat > "$tmp"
    python3 "$KIT/common/data.py" atomic-copy "$tmp" "$target"
    rm -- "$tmp"
}

write_file() {
    local target=$1 mode=${2:-600} tmp
    tmp=$(mktemp "$STATE/stage/file.XXXXXXXX")
    cat > "$tmp"
    chmod "$mode" "$tmp"
    put_file "$tmp" "$target"
    rm -- "$tmp"
}

rule_add() {
    local tool=$1 table=$2 chain=$3; shift 3
    if ! "$tool" -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null; then
        record_undo "$tool" -w 5 -t "$table" -D "$chain" "$@"
        "$tool" -w 5 -t "$table" -I "$chain" 1 "$@"
    fi
}

unit_enable() {
    local u=$1
    if ! systemctl is-enabled --quiet "$u" 2>/dev/null; then
        record_undo systemctl disable "$u"
        systemctl enable "$u" >/dev/null
    fi
}

unit_start() {
    local u=$1
    if ! systemctl is-active --quiet "$u"; then
        record_undo systemctl stop "$u"
        systemctl start "$u"
    fi
}

take_backup() {
    local dest
    dest="$STATE/backups/$(date -u +%Y%m%dT%H%M%S.%N)"
    install -d -m 0700 "$dest"
    ip -j -4 rule show > "$dest/rules.json"
    ip -j -4 route show table all > "$dest/routes.json"
    iptables-save > "$dest/iptables.v4"
    ip6tables-save > "$dest/iptables.v6"
    systemctl list-unit-files --no-pager > "$dest/unit-files.txt"
    local paths=() p
    for p in etc/amnezia etc/iptables etc/ufw etc/paco-deploy etc/systemd/system usr/local/lib/paco-deploy usr/local/sbin/paco-awg.py var/lib/paco-awg var/lib/paco-deploy/keys var/lib/paco-deploy/clients var/lib/paco-deploy/manager-quarantine root/awg-client; do
        [[ ! -e /$p ]] || paths+=("$p")
    done
    # Исходная SQLite из tar может быть несогласованной; эталон — отдельная backup API copy.
    if [[ -f /var/lib/paco-awg/traffic.sqlite3 ]]; then
        python3 "$KIT/common/data.py" sqlite-copy /var/lib/paco-awg/traffic.sqlite3 "$dest/traffic.consistent.sqlite3"
    fi
    tar --acls --xattrs --numeric-owner -czf "$dest/files.tar.gz" -C / "${paths[@]}" 2>/dev/null || die 'Backup tar не завершён; ничего не переключено'
    tar -tzf "$dest/files.tar.gz" >/dev/null
    (cd "$dest" && sha256sum files.tar.gz > SHA256SUMS)
    chmod -R go-rwx "$dest"
    note "BACKUP: $dest (секретный; скопировать оператором вне VPS)"
    BACKUP=$dest
}

begin_tx() {
    take_backup
    local id deadline
    if [[ $ACTION == B-clients && -f $STATE/active ]]; then
        id=$(cat "$STATE/active")
        TX=$STATE/transactions/$id
        TIMER=$(cat "$TX/timer")
        systemctl is-active --quiet "$TIMER.timer" || die 'Нет действующего rollback timer'
        note "Продолжается транзакция ENTRY $id; исходный deadline НЕ продлевается"
        return
    fi
    id=$(date -u +%Y%m%dT%H%M%S)-$(cat /proc/sys/kernel/random/uuid)
    TX=$STATE/transactions/$id
    install -d -m 0700 "$TX"
    : > "$TX/undo.jsonl"
    printf '%s\n' "$BACKUP" > "$TX/backup-path"
    printf '%s\n' "$ACTION" > "$TX/action"
    printf '%s\n' "$SCENARIO" > "$TX/scenario"
    printf '%s\n' "$ROLE" > "$TX/role"
    printf '%s\n' "$id" > "$STATE/active"
    # Локальная копия кода для автономного rollback; не зависит от распакованного ZIP.
    install -d -m 0700 "$RUNTIME/common"
    local p
    for p in data.py rollback-runtime.sh runtime.sh; do
        install -m 0700 "$KIT/common/$p" "$RUNTIME/common/$p"
    done
    TIMER=paco-rollback-$id
    printf '%s\n' "$TIMER" > "$TX/timer"
    deadline=$(date -u -d "+$ROLLBACK_SECONDS seconds" '+%Y-%m-%d %H:%M:%S UTC')
    write_new_file "/etc/systemd/system/$TIMER.service" <<EOF
[Unit]
Description=PACO automatic rollback $id
[Service]
Type=oneshot
UMask=0077
ExecStart=$RUNTIME/common/rollback-runtime.sh --apply $id
StandardOutput=null
StandardError=null
EOF
    write_new_file "/etc/systemd/system/$TIMER.timer" <<EOF
[Unit]
Description=PACO rollback deadline $id
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$TIMER.service
[Install]
WantedBy=timers.target
EOF
    chmod 0600 "/etc/systemd/system/$TIMER."{service,timer}
    systemd-analyze verify "/etc/systemd/system/$TIMER.service" "/etc/systemd/system/$TIMER.timer" >/dev/null 2>&1 || die 'Некорректный rollback unit; переключение запрещено'
    systemctl daemon-reload
    systemctl enable --now "$TIMER.timer" >/dev/null
    systemctl is-active --quiet "$TIMER.timer" || die 'Rollback timer не вооружён'
    note "ROLLBACK ARMED: $id; deadline $deadline"
    # Отложенная команда старого AWG1 применяется ПОСЛЕ восстановления файлов/rules.
    if [[ $ACTION == A-switch-entry ]]; then
        quiet awg showconf awg1
        awg showconf awg1 > "$TX/awg1.runtime.conf" 2>/dev/null
        record_undo "$RUNTIME/common/runtime.sh" --apply restore-transit "$TX/awg1.runtime.conf"
    fi
    printf '%s %s %s START\n' "$(date -u +%FT%TZ)" "$ACTION" "$ROLE" >> "$STATE/operations.log"
}

finish_pending() {
    printf '%s %s %s PENDING_VERIFICATION\n' "$(date -u +%FT%TZ)" "$ACTION" "$ROLE" >> "$STATE/operations.log"
    note 'Изменения ожидают проверки. Rollback timer остаётся активным.'
    note 'Не повторяйте setup: используйте verify/commit либо rollback.'
}
