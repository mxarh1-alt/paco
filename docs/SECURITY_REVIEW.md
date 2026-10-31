# Независимый технический разбор и ограничения

Это инженерный self-review подготовленного комплекта, не разрешение production и не заявление об отдельном внешнем ревью. Кира/оператор должны проверить исходники и испытать два тестовых VPS. Исходные документы использованы как факты/ТЗ; содержащиеся в них команды не запускались на действующих серверах.

## Критические замечания к исходному комплекту

| Риск | Что известно | Решение в коде / оставшийся STOP |
|---|---|---|
| Совместимость AWG | В аудите лишь installed; версии неизвестны | Точные версии пакетов для новых Ubuntu24.04 amd64, профиль именно AWG1, kernel round-trip, затем handshake. На ENTRY A ничего не обновляется. Неизвестная версия/параметр — NO-GO |
| Скрытый fallback в main | Удаление рабочего table100 route было проверено, полный down AWG1 нет | Независимые source rules/unreachable/первый FORWARD DROP, guard до AWG0, нет удаления fallback в route-down; два отдельных fault drill |
| Клиентский IPv6 | Не доказан | Захват ::/0 или OS block + тест native IPv6; серверный DROP сам по себе недостаточен. Без evidence apply блокируется |
| Rollback и SSH | Свежий whitelist/консоль не зафиксированы | Явный source CIDR, actual listener/SSH_CONNECTION, console/second-session flags, backup и постоянный deadline timer до опасного шага |
| Legacy hooks/units | Полных текстов нет | A требует explicit config path, отсутствия AWG0 hooks/опасного ExecStop legacy guard, отдельного аудита функций AWG1 hooks и реального dependency graph. Нет автоматической догадки/исправления |
| UFW EXIT | Только исторический известный статус/исправленная ошибка before.rules | Старый EXIT не трогаем. На новых явно другой проверяемый вариант iptables-nft + own guard; active/конкурирующий manager блокируется |
| Manager/history | Нет исходника/бэкапов, tar SQLite не доказывает consistency | В A не изменяется; B — API backup/integrity check и offline quarantine. AST отчёт проверяет известные hardcoded поля без исполнения. Активация/адаптация неизвестного кода STOP |

## Внесение изменений и секреты

Нет автоматических SSH, SCP, reboot, OpenVPN, изменения main default, отключения глобального IPv6, очистки firewall или route table100. Все публичные wrappers по умолчанию read-only dry-run; для apply — root, полный plan token, отдельное согласие A, проверка VPS и защищённые локальные файлы. Конфиги/inventory разбираются как литеральные данные; не source/eval и не shell interpolation. Python bytecode запись в dry-run запрещена через PYTHONDONTWRITEBYTECODE.

Приватные ключи/PSK не входят в config env, argv или ответ. Ключи создаются только локально после apply. `awg syncconf/setconf` stderr скрыт, чтобы parser error не вывел секретную строку. AWG private profiles, candidates, runtime snapshots, backups — только root0700/0600, без stdout. Лог `/var/lib/paco-deploy/operations.log` фиксирует статусы/этапы/UTC, без private values. Тестовые данные генерируются во временных файлах и не являются рабочими ключами.

Не включайте shell tracing `bash -x`, не используйте `awg showconf`, `awg show ... dump`, `cat` private configs для передачи в чат/журнал. После распаковки root-код должен принадлежать root, а каталоги быть недоступны для записи другим. Хеши ZIP не дают независимой аутентификации источника; проверяется доверенная доставка и экспертное ревью.

## Fail-closed при boot/ошибке

Guard не требует AWG0/AWG1 и не имеет ExecStop. Нет device lifetime rule/fallback. AWG1 route hooks удаляют только рабочий default table100; fallback и source rules остаются. Все новые AWG units требуют успешный guard. Если выше уже существовавшего guard обнаружен чужой ACCEPT, guard завершается ошибкой и клиентский интерфейс не должен стартовать; чужие правила не переставляются вслепую. Испытать также startup AWG1 failure/отсутствие endpoint, а не только route deletion.

На ENTRY действует anti-spoof и DROP всего трафика с AWG0 в любой выход, кроме AWG1; отдельный source-specific DROP совпадает с исходным PACO. IPv6 AWG0 блокируется без глобального отключения IPv6 сервера. UDP60334 IPv6 блокируется на обоих узлах, чтобы не оставлять обход IPv4 peer whitelist. Новые clients имеют ::/0 capture, но реальные OS/client-app tests остаются обязательными.

## Rollback review

Каждая опасная операция покрыта собственными обратными командами, а не глобальным restore. Snapshot files публикуются атомарно, inverse journal fsync; успешные inverses имеют persistent checkpoints для повторного rollback. Для уже отсутствующего собственного iptables/rule проверяется фактическое отсутствие, а ошибки доступа не объявляются успехом.

Важная проверенная конструкция A: rollback **не останавливает** новый guard. Иначе Requires-зависимость могла бы остановить AWG0 при попытке убрать guard. Возвращаются drop-ins/files и исходный AWG1; активный oneshot guard не имеет ExecStop, а старый исходный failclosed проверен до cutover. На B stop новых клиентских units допустим, но все client identities/configs сохраняются. Callback при любой незавершённой операции оставляет active marker и пишет FAILED.

Между двумя узлами нет распределённой транзакции. Firewall update, atomic file replacement и netlink syncconf — отдельные шаги, покрытые snapshot/timer; не обещается нулевая пауза. Оператор координирует deadlines и проверяет оба узла. Загрузка/установка пакетов, DKMS и созданные секретные файлы автоматическим rollback не удаляются; установка разрешена только на новых VPS с внешним snapshot. Сохранённые backups не заменяют тест восстановления.

## Остаточные риски и NO-GO

- Не проведены VPS/kernel data-plane/NAT/IPv6/SSH/reboot tests. Static units использовали fixtures для базовых/legacy служб; реальный graph может отличаться и блокировать A.
- Реальная версия AWG1 A и её padding/header значения неизвестны. Нельзя считать новые AWG3.1 пакеты обратно совместимыми без фактического handshake/клиентского теста. Явный STOP лучше выдуманных параметров.
- Иные ОС/архитектуры, legacy firewall, native nft manager, активный UFW, provider NAT, Secure Boot без подписанного DKMS, I1-I5/HeaderProtectionKey/диапазоны H не поддержаны автоматически.
- Host INPUT policies глобально не заменяются; это scoped PACO firewall, не полный hardening. Неучтённые host services/IPv6 SSH/provider rules требуют отдельного решения. Существующий `eth1` A не трогается.
- Нельзя проводить параллельные firewall/client/manager изменения во время миграции. Точное правило другого процесса, добавленное одновременно, невозможно надёжно отличить от собственного по одному netfilter состоянию.
- Persistent timer зависит от живого systemd/диска/часов. При потере VPS, зависании ядра, нехватке диска или пропавшей консоли нужна внешняя процедура восстановления; скрипт не обещает недостижимую гарантию доступа.
- Acceptance JSON — локальная аттестация оператора, не подписанное удалённое доказательство и не автоматическое измерение клиентского IP/DNS/HTTPS.
- B manager activation остаётся отдельным STOP до локального получения/аудита исходника и units. История сохранена offline, статистика в работе не заявляется.

GO для production возможно только после устранения неизвестных, полного теста двух VPS, ревью Кирой и отдельного согласия оператора. Текущий статус — **REVIEWED STATICALLY**.
