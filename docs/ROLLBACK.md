# Откат и сохранение доступа

## Что сохраняется до изменений

`/var/lib/paco-deploy/backups/<UTC timestamp с наносекундами>/`: полный защищённый tar известных каталогов AWG, systemd, firewall, менеджера/клиентских файлов, новых keys/clients/quarantine; read-only snapshots IPv4 rules/routes, v4/v6 iptables и unit enabled states. Существующая SQLite дополнительно копируется через `sqlite3.Connection.backup()` и `integrity_check`. Эта отдельная `traffic.consistent.sqlite3` — эталон, а не случайно попавшая в tar живая БД. Права каталога 0700/файлов 0600, tar проверяется чтением и SHA256.

`transactions/<ID>/`: append-only обратный JSONL-журнал, прежние файлы/режимы, action/role/scenario, имя timer, ссылка на backup. A дополнительно сохраняет runtime AWG1, SHA AWG0, manifest peers, SHA runtime peer set и менеджера. Runtime AWG1 содержит private key/PSK; его нельзя показывать или включать в публичный отчёт.

Нельзя использовать глобальный `iptables-restore` из backup без отдельного анализа: он может стереть новые SSH/чужие изменения. Автоматический откат выполняет только точные обратные команды собственного журнала. Чужие правила/клиенты не чистятся. Main default не меняется ни при применении, ни при откате.

## Автоматическая страховка

До опасных действий создаются `paco-rollback-<ID>.service` и `.timer`. Таймер enabled+active, абсолютный UTC `OnCalendar`, `Persistent=true`, точность 1s. Процессам/таймерам не надо пережить reboot: unit-файлы и deadline сохранены на диске. Пропущенный deadline приводит к запуску после загрузки. Истёкший или failed timer не является гарантией успешного отката — проверить журнал и состояние.

Timer callback и ручной оператор используют один `flock`; перед откатом active marker проверяется повторно. Одновременно commit и rollback выполнить изменения не могут. Pending timer не продлевается при добавлении клиента в B. 300..3600 секунд задаются заранее, достаточно для согласованной приёмки; если времени недостаточно, безопасно откатиться и спланировать другое окно.

В A обратное восстановление старого runtime AWG1 зарегистрировано первым и исполняется последним, после возврата конфигов/rules/MTU. Старая ENTRY policy и DROP проверяются до cutover. AWG0 не перезапускается, keys/peers/менеджер не изменяются. При невозможности безопасно проверить legacy hooks A блокируется заранее.

В B вновь созданные units могут быть остановлены/disabled, правила новых операций возвращаются к исходным. **AWG0 config, клиентские private profiles и key files не удаляются.** Может сохраниться защитный unreachable fallback без policy rule; он не затрагивает main. После rollback сохранить и сверить manifest, не удалять клиента или конфиг, чтобы выдать VPS за пустой.

## Ручной откат

В консоли/сохранившемся SSH того же узла:

```bash
bash common/rollback.sh --snapshot ID --dry-run
bash common/rollback.sh --snapshot ID --apply --confirm 'APPLY rollback'
```

Сценарий A предоставляет тот же wrapper `scenario-A/04-rollback-entry.sh`. Применение требует root, точного ID текущей active транзакции и явного подтверждения. Исправные AWG/IPv6 evidence/inventory для аварийного отката не требуются. Это исключение относится только к уже одобренному обратному журналу. Нельзя выбрать произвольный старый snapshot и заменить более новую работающую сеть.

Если исходный распакованный комплект утрачен, после просмотра active ID оператор может вызвать сохранённый callback:

```bash
/usr/local/lib/paco-deploy/common/rollback-runtime.sh --apply ID
```

Он обслуживает только собственную активную транзакцию. Не редактировать undo.jsonl вручную и не публиковать его/backup. При любой ошибке callback оставляет active marker, пишет `ROLLBACK_FAILED`; service становится failed. Не утверждать, что откат завершился, по одному факту срабатывания timer. Через консоль сверить конкретные файлы/rules/route/handshake и восстановить только недостающий элемент после ревью.

## Проверка результата

1. Новый SSH из разрешённого источника, прежний host default, адреса WAN/eth1 не изменились.
2. В A AWG0 active, SHA конфига/peer set прежние, manager source тот же, `paco-awg-traffic.timer` active.
3. Старый AWG1 endpoint/public peer восстановлен; свежий handshake/пинг; внешний IP тестового клиента соответствует **старому** EXIT. Current inventory нового EXIT для `verify` уже не подходит — используйте старую локальную контрольную информацию/аудит.
4. Policy 99/100, unreachable default и исходный client DROP сохранены. Не выполнять flush table100.
5. В B сохранить все keys/profiles и убедиться, что новые клиенты не выходят через ENTRY WAN; если AWG0 остановлен — это ожидаемый безопасный исход отката нового узла.
6. Сохранить protected backup вне VPS. Пример забора на компьютере оператора: `scp -P SSH_PORT -r root@NODE:/var/lib/paco-deploy/backups/TIMESTAMP ./private-backups/`. Заменить маркеры после проверки адреса, настроить безопасные права на стороне назначения, сверить SHA256. Этот ZIP не выполняет передачу автоматически.

Снятие страховки — только через `A-commit`/`B-commit` после успешных текущих локальных проверок и свежей acceptance; отдельной команды «force cancel» нет. Старые rollback unit-файлы сохраняются как след операции; inactive timer без active marker ничего не откатывает. Чистку архивов/units выполнять отдельным согласованным действием после внешней копии.
