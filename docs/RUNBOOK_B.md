# PACO v2: B — два новых VPS

Новые public IP, hostname, WAN, точная Ubuntu 24.04 и ядра берутся **с новых узлов**. Публичные адреса старой Москвы/Алматы не копировать. `NODE_ROLE` и SSH whitelist задаются отдельно на каждом сервере. Комплект выбирает iptables-nft; UFW/nftables manager выключать вслепую нельзя — при активном manager STOP.

## 1. Подготовить версии и идентичности

Оператор проверяет консоль, второй SSH, hostname/ОС/ядро/архитектуру/WAN, конфликты, RAM+swap/диск. До генерации ключей отдельное согласие. Сначала read-only preview, затем на обоих новых VPS:

```bash
bash common/install-awg.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY install-awg' --console-confirmed --second-session-confirmed
bash common/generate-transit-identity.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY keys' --console-confirmed --second-session-confirmed
```

Перенести только public keys в оба inventory. Для двух новых узлов можно выбрать `config/transit-profile-B.conf.example` как одинаковый кандидат, но он ещё должен пройти kernel probe, handshake и лабораторную приёмку. Скопировать как `/root/paco/transit-profile.conf`, chmod 0600. Параметры AWG0/клиента фиксированы подтверждённым PACO-профилем; совместимость AWG0 с клиентским приложением обязательно тестируется.

`CLIENT_IDENTITY_STRATEGY`:

- `RESTORE_FROM_OWNER_BACKUP`: root-only локальный AWG0 server config с исходным private key и всеми peers/PSK. Валидатор отбрасывает hooks, неверные сети/порты/профиль и широкие/дублирующиеся peer IP. Исходные клиентские private profiles остаются у владельца. v2 сохраняет `# имя` перед [Peer]/внутри секции, прочие standalone/inline комментарии и исходный порядок peers; имена не восстанавливаются догадкой по IP. После импорта локально сверить имя ↔ public key ↔ AllowedIPs с backup. Kernel stripped config не содержит комментарии. Без имени в исходнике новое имя не изобретается; дублирующий PublicKey блокирует restore. Без server private key бесшовный перенос невозможен.
- `REISSUE_ALL`: новый серверный AWG0 key, новые клиентские private profiles локально на ENTRY. Раздача оператором по защищённому каналу. Старые профили не начнут работать автоматически.

В обоих случаях новый ENTRY IP требует сменить Endpoint в клиентских профилях. Этот вариант кода использует явный IPv4:port. Вариант DNS/сохранения старого адреса требует отдельной проверки владения/TTL/соответствия; автоматически не реализован.

Сначала протестировать клиентскую политику `::/0`/native IPv6, выставить evidence и внешние backup/console flags. Если на выбранной платформе полный IPv6 захват без native leak не подтверждён — NO-GO.

## 2. Новый EXIT, потом ENTRY

На EXIT:

```bash
bash scenario-B/01-setup-exit.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY B-setup-exit' --console-confirmed --second-session-confirmed
```

На ENTRY:

```bash
bash scenario-B/02-setup-entry.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY B-setup-entry' --console-confirmed --second-session-confirmed
bash scenario-B/03-connect-servers.sh --config /root/paco/config.env --inventory /root/paco/inventory.env --dry-run
```

Шаг connect только проверяет transit ping и свежий handshake одного ожидаемого peer; сам не меняет серверы. Guard существует до AWG0/AWG1, независимо от их успеха. ENTRY пока без клиентского AWG0. У обоих узлов armed timers; записать ID/deadline. Нельзя объявлять готовность по PID/открытому порту.

## 3. Восстановить клиентов или создать первый тестовый профиль

При восстановлении `RESTORE_AWG0_FILE` — локальный файл 0600, не загружать его в чат. При перевыпуске сначала один новый клиент, например testpaco. Для verify `TEST_CLIENT_IP` должен соответствовать этому реально добавленному peer (первый свободный обычно .2, но не предполагать — проверить локальный выданный профиль).

```bash
bash scenario-B/04-restore-clients-or-enroll.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --name testpaco --apply --confirm 'APPLY B-clients' --console-confirmed --second-session-confirmed
```

`--name` используется только для REISSUE_ALL; при restore его можно опустить. `--client-public-key-file` пока не поддерживается: комплект генерирует ключ на узле после согласия и сохраняет полноценный профиль. Имя повторно не создаёт другого peer/IP/key; при противоречии manifest — STOP.

Шаг продолжает active транзакцию B-setup-entry, не сбрасывая deadline. Повторный setup запрещён. Новые профили находятся только в `/var/lib/paco-deploy/clients/*.conf` (0600); их содержимое не выводится. Импорт не заменяет существующие идентичности; hooks из исходного backup не исполняются. AWG0 стартует только после guard; дальнейшее добавление использует syncconf, без restart остальных клиентов.

Восстановление менеджера: `MANAGER_MODE=NONE` — явный выбор работы без автоматического учёта. При `RESTORE_OFFLINE` владелец предоставляет root-only каталог с `paco-awg.py` и **консистентной** `traffic.sqlite3`; комплект сохраняет их в `/var/lib/paco-deploy/manager-quarantine/`, проверяет SQLite, но не исполняет код/units. Нужен отдельный аудит оригинала v0.2.4 и hardcoded ENDPOINT/INTERFACE/NET. Не переносить неизвестный timer автоматически. Сохранённая история не означает работающую статистику.

## 4. Приёмка, reboot и commit

Выполнить [acceptance checklist](../tests/acceptance_checklist.md): локальные verify на обоих узлах, внешний клиентский IP нового EXIT, HTTPS/DNS/IPv6, оба failclosed drill, rollback drill в лаборатории, внешние бэкапы. Затем вручную reboot EXIT, проверить; reboot ENTRY, проверить. Ни один скрипт reboot не вызывает.

Свежий acceptance.json на каждом узле должен отражать текущие boot IDs и действующий состав peers. После этого на ОБОИХ:

```bash
bash scenario-B/05-verify-and-commit.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY B-commit' --console-confirmed --second-session-confirmed
```

Только после успешной приёмки первого клиента продолжать миграцию остальных. Следующее добавление нового клиента можно делать отдельной B-clients транзакцией после предыдущего commit; повторная попытка при неизвестной active транзакции не выполняет изменений. Откат не удаляет клиентов: новые keys/configs сохраняются, вновь созданный unit может быть остановлен. После отката нового развёртывания сохранённый AWG0 препятствует ложному распознаванию VPS как пустого; дальнейший запуск — по восстановленному manifest/после ревью, без удаления файлов ради прохождения preflight.
