#!/usr/bin/env bash
# Внутренний timer callback; только после уже одобренного --apply.
set +x
set -Eeuo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1
if [[ ${1:-} != --apply ]]; then
    printf '%s\n' 'DRY-RUN: callback одобренного rollback timer; используйте common/rollback.sh для ручного отката.'
    exit 0
fi
shift
[[ $EUID == 0 && ${1:-} =~ ^[0-9]{8}T[0-9]{6}-[a-f0-9-]{36}$ ]] || exit 2
root=/var/lib/paco-deploy
tx=$root/transactions/$1
[[ -d $tx && -f $root/active && $(cat "$root/active") == "$1" ]] || exit 0
exec 9> /run/lock/paco-deploy.lock
flock 9
# Проверить снова после ожидания commit/операции.
[[ -f $root/active && $(cat "$root/active") == "$1" ]] || exit 0
trap 'printf "%s ROLLBACK_FAILED %s\n" "$(date -u +%FT%TZ)" "$1" >> "$root/operations.log"' ERR
python3 /usr/local/lib/paco-deploy/common/data.py undo "$tx"
timer=$(cat "$tx/timer")
systemctl disable --now "$timer.timer" >/dev/null 2>&1 || true
printf '%s ROLLED_BACK %s\n' "$(date -u +%FT%TZ)" "$1" >> "$root/operations.log"
mv "$root/active" "$tx/rolled-back"
