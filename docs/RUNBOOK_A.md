# A — существующая ENTRY, новый EXIT

Версия 2.0.0. Статус этого runbook: подготовлен и проверен локально, **не применён к VPS**. Сначала лаборатория, затем окно оператора. Старый EXIT остаётся рабочим до завершения всей приёмки. Нельзя считать его доступность доказанной историческим аудитом.

## 0. Сбор фактов без изменения сети

На старой ENTRY оператор вручную проверяет `hostname -s`, `/etc/os-release`, `uname -r`, `ip -br -4 a`, `ip -4 route show default`, `awg --version`, `iptables --version`, `ip6tables --version`, SSH и версии пакетов. Старый `eth1=10.200.200.4/24` не изменять. Два совпадающих default eth0 не очищать.

На новом EXIT собрать те же сведения; подтвердить Ubuntu 24.04 amd64, WAN с реальным публичным IPv4, свободные порты, достаточный диск/RAM, отсутствие чужого VPN/firewall. Заполнить inventory на каждом узле. `ENTRY_AWG_TOOLS_VERSION` — полная строка фактического `awg --version`, в кавычках.

Для ENTRY проверить локально, не публикуя конфиги/ключи:

```bash
systemctl show awg-quick@awg1.service -p ExecStart -p ExecStop
systemctl cat paco-failclosed.service
ip -4 rule show
ip -4 route show table 100
iptables -C FORWARD -i awg0 -s 10.77.77.0/24 ! -o awg1 -j DROP
awg show awg1 public-key
```

ExecStart/ExecStop должны быть прямыми awg-quick up/down с точным аргументом `/etc/amnezia/awg1.conf`. Совпадение подстроки в .conf.bak, shell wrapper или цепочка нескольких команд не принимаются. Если используется bare `awg1`, другой путь или symlink — **STOP**, разобрать реальный unit и выбранную версию awg-quick, не создавать угаданный symlink. Нельзя автоматически мигрировать unit работающей системы ради прохождения проверки.

Экспортирует **только числовые параметры протокола**, не private key:

```bash
umask 077
python3 common/data.py export-profile /etc/amnezia/awg1.conf > /root/paco/transit-profile.conf
```

При отсутствующем поле/новых I1-I5/HeaderProtectionKey/диапазонах H вывод не считается готовым профилем: удалить неполный файл после просмотра, **NO-GO**, определить фактический протокол в лаборатории. Не подставлять клиентский AWG0 профиль вместо AWG1. Одинаковый несекретный transit-profile передать новому EXIT по согласованному каналу.

`PreUp/PostUp/PreDown/PostDown` AWG0 блокируют A до отдельного аудита; основной комплект их не переписывает. AWG1 hooks в новом конфиге не сохраняются: вместо них независимый guard и явные route hooks. Это предотвращает удаление policy/fallback при `awg1 down`. Требуется проверить, что legacy hooks не содержат иных необходимых функций; при наличии таких функций **NO-GO** до отдельного ревью. Legacy failclosed с ExecStop не поддерживается. Реальные зависимости дополнительно проверяются systemd-analyze на месте; цикл — STOP, не ослаблять Requires/Before.

Подтвердить native IPv6 каждого клиента, внешний backup и provider console/два SSH. Указать `SSH_SOURCE_CIDR` оператора (не IP сервера), `PROVIDER_FIREWALL_VERIFIED=YES`, `OFFSITE_BACKUP_VERIFIED=YES`, `LEGACY_POLICY_AUDITED=YES` и evidence только после проверок.

## 1. Подготовить новый EXIT

`NODE_ROLE=exit`. Сначала каждый шаг с `--dry-run`; для установки отсутствие AWG допускается, но сам VPS/ОС обязаны совпасть с inventory. Примеры apply после отдельного согласия:

```bash
bash common/install-awg.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY install-awg' --console-confirmed --second-session-confirmed
bash common/generate-transit-identity.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY keys' --console-confirmed --second-session-confirmed
```

Записать **только public key** нового EXIT в оба inventory. Public key ENTRY получить read-only из активного AWG1; его private key не перевыпускать и не передавать. Если у старого transit peer есть PSK, одинаковый PSK владелец размещает только локально 0600 на обоих узлах и задаёт `TRANSIT_PSK_FILE`. Не передавать PSK в сообщениях, argv или переменных окружения.

```bash
bash scenario-A/01-prepare-new-exit.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY A-prepare-exit' --console-confirmed --second-session-confirmed
```

Фиксируется backup, вооружается rollback timer, проверяется profile через временный `pacoprobe` без адресов/маршрутов и с ListenPort=0, создаются guard, AWG1, client-only NAT, reverse route. Убедиться в root-only файлах и enabled units, правильном UDP whitelist. До переключения ENTRY handshake может отсутствовать — это ожидаемо, не готовность полного каскада. Временный тестовый peer здесь не создаётся. Для его использования потребовался бы отдельный согласованный профиль/порт; основной комплект не вмешивается в активный peer на pre-stage.

Сохранить ID EXIT и UTC deadline. Успеть до него либо выполнить rollback и повторно подготовить окно. Таймер не продлевается молча.

## Проверка исправленного порядка v2

На Москве guard следует за network-online.target и paco-failclosed, но не требует Before=network-pre. AWG0/1 через drop-ins требуют guard и следуют за ним. На новых EXIT используется отдельный ранний template без legacy dependency. В apply до probe/cutover создаются staged guard/drop-ins, затем standalone systemd-analyze verify читает реальные unit-файлы хоста через overlay. Меняется только executable path ещё не установленного helper на исходник KIT; ordering идентичен. Ошибка, timeout или cycle — NO-GO до любых изменений активных unit files/firewall. После установки повторяется verify с конечным путём.

Preview остаётся без записи файлов и не удостоверяет будущий host graph. Для отдельной локальной проверки staged-файлов оператор может вызвать units.py stage-a и verify-live-a в защищённом временном каталоге, но это ещё не разрешение на cutover. Не заменять настоящий host graph fixture-моделью. В лаборатории обязательны reboot и startup AWG1 failure.

## 2. Переключить ENTRY

`NODE_ROLE=entry`, известный новый public key/endpoint EXIT, второй SSH и консоль открыты. Сделать preview, проверить полный план. Затем отдельное согласие:

```bash
bash scenario-A/02-stage-and-switch-entry.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY A-switch-entry' --console-confirmed --second-session-confirmed --entry-cutover-approved
```

Алгоритм: локальное чтение прежнего private key AWG1 → кандидат одного peer → module probe → backup/runtime snapshot → постоянный rollback timer → fingerprint AWG0/менеджера → независимый persistent guard и drop-ins → whitelist нового EXIT → атомарный AWG1 файл → сохранение/установка MTU AWG1 1380 → один `awg syncconf` → table100 route-up. Никаких restart AWG0, изменения клиентов, локального NAT на ENTRY, изменения main default/eth1.

Файловая запись и netlink syncconf — разные операции, распределённой атомарности нет. Окно минимально, а последствия частичного отказа покрываются обратным журналом и сохранённым runtime old AWG1. Любая ошибка не снимает timer. Не продолжать массовые клиентские операции параллельно.

## 3. Проверить и зафиксировать на обоих узлах

На каждом узле:

```bash
bash common/verify.sh --config /root/paco/config.env --inventory /root/paco/inventory.env --dry-run
```

На ENTRY дополнительно сравнить manifest AWG0, исходник менеджера, таймер статистики. Проверить клиентский внешний IPv4 = новый EXIT, HTTPS/DNS, отсутствие native IPv6. Затем в согласованном окне два fault drill по [acceptance](../tests/acceptance_checklist.md), ручной reboot сначала EXIT, затем ENTRY, каждый раз SSH/units/routes/client. Таймер переживает reboot, но его deadline прежний. Если окно истекло — не объявлять успех, определить состояние отката.

На каждом узле заполнить свежий `acceptance.json` с фактическими boot IDs, timestamp и fingerprint/count ENTRY. Только тогда:

```bash
bash scenario-A/03-verify-and-commit.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY A-commit' --console-confirmed --second-session-confirmed
```

Commit снимает timer только этого узла. Если один узел прошёл, другой нет, вся миграция не принята. При любом отказе вернуться к старому EXIT на ENTRY, сохранить новый EXIT для диагностики; старый не выключать.

## 4. Откат

На ENTRY `scenario-A/04-rollback-entry.sh --snapshot ID --apply --confirm 'APPLY rollback'`. На новом EXIT — `common/rollback.sh` с его собственным ID, когда безопасно. Сначала вернуть клиентский каскад на старый EXIT, затем откатывать новый. Аварийный wrapper не требует исправного AWG/preflight: он возвращает только active transaction. См. [ROLLBACK](ROLLBACK.md).
