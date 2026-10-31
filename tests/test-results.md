# PACO v2.0.0: фактические результаты — 31.10.2026

**Статус: REVIEWED STATICALLY. TESTED IN LAB / PRODUCTION-APPROVED не присваивались.** Все проверки выполнены в локальной облачной рабочей среде без root-применения сценариев, без SSH к VPS, без изменения действующей инфраструктуры.

| Проверка | Реальный результат | Предел доказательства |
|---|---|---|
| Исходный SHA256SUMS | 13/13 OK | Целостность приложенных исходных документов |
| `bash -n` | PASS, 22 Bash-файла включая два экземпляра исходного audit | Только синтаксис |
| ShellCheck v0.10.0 `-x -P SCRIPTDIR -S style` | PASS, без diagnostics/исключений правил | Не проверяет kernel/data plane |
| Python AST | PASS, все Python helper/test files | Только синтаксис |
| `tests/test_offline.py` | **51 выполнено, 51 PASS; 0 failed, 0 skipped** | Temp files, mocks, реальный userspace pubkey/enrollment; не привилегированный deploy |
| systemd-analyze verify | 5 моделей: 3 положительных PASS, 2 отрицательных корректно отвергнуты | Изолированный root, сетевой manager/online/legacy ordering моделируется; реальный graph ENTRY не проверен |
| Реальный AWG tools parser | PASS: J/S1-S4/H1-H4 приняты до netlink; неизвестное поле отклонено | Интерфейс не создавался, операция не дошла до изменения kernel interface |
| PPA пакет | SHA256 .deb совпала с HTTPS Packages, version v3.1.20260812 | APT signature в текущей среде не проверялась; APT на VPS обязан проверить её штатно |
| Официальные source refs | 4 загруженных source файла совпали с pinned commits | Не доказывает runtime compatibility |

Дополнительно к v1 проверены: сохранение # galt/# testpaco до/внутри [Peer], inline/Unicode/header комментариев и заметок удаляемого SaveConfig; стабильность parse/render; исключение metadata из stripped config; duplicate PublicKey rejection; manager AST report без исполнения исходника и с запретом activation; точные ExecStart/ExecStop paths AWG1; A/new-node выбор templates; неизменность [Unit] в проверочном overlay и использование host search paths; NO-GO на cycle/error без утечки сырого stderr.

Offline-тесты также проверяют: неизвестные/опасные env поля и shell-подстановки, совпадение ОС B/Endpoint, подсети/SSH whitelist, profile/header validation, атомарность/права/запрет symlink, сохранение server/private peer identity при A/restore B, запрет молчаливого удаления PSK, SQLite backup API/целостность/строки, durable inverse и checkpoint повторного rollback, реальную идемпотентную выдачу peers без дубликатов с full-tunnel профилем, отсутствие изменений в dry-run dispatcher, root gate apply, взаимное исключение apply/dry-run, отсутствие table100 на новом узле и отличие от permission error, missing S3 kernel round-trip NO-GO.

В tests временные синтетические keys не являются рабочими секретами; значения не включены в журнал. Для actual pubkey/parser использовался inspected AWG binary вне deploy ZIP через PACO_TEST_AWG_BIN. В повторном запуске без этой переменной один optional test будет явно skipped; это не равно выполненным здесь 51 PASS. При root ещё один root-gate test явно skipped, как отмечено Кирой при проверке v1.

## Проверки systemd: что доказано

Модель обычной сети воспроизводит cycle v1 (legacy After online, guard Before pre). Тот же сценарий с A guard v2 проходит; ранний new-node guard B и A EXIT также проходит. Другой неправильный legacy After AWG1 по-прежнему отвергается — guard не ослабляется ради PASS. Всего 3 успешных verify и 2 ожидаемых отказа модели, не пять реальных VPS.

`units.py verify-live-a` добавлен для будущего узла: его построение overlay/ошибки протестированы с mocked subprocess. Сам standalone verify с реальными файлами Москвы не запускался. Ни этот mock, ни fixture verify не выдаются за HOST-GRAPH-VERIFIED или reboot PASS.

## Не выполнялось

- Установка APT/PPA/DKMS на тестовые или рабочие VPS; проверка kernel module под реальными новыми ядрами/Secure Boot.
- Привилегированное создание pacoprobe, `awg setconf/syncconf` на действующем интерфейсе, real server handshake.
- Реальные ip rule/route/firewall/NAT изменения и проверка data plane, клиентский внешний IP/DNS/HTTPS/native IPv6.
- Запуск автоматического rollback timer на VPS, проверка SSH/provider console и fault injection в реальную сеть.
- Ручной reboot EXIT/ENTRY и проверка настоящего legacy unit dependency graph.
- Восстановление частных owner backups или менеджера v0.2.4, работа SQLite history после реального переноса.

Эти пункты **UNRUN**, а не passed/skipped в offline runner. Дальнейшие действия описаны в acceptance_checklist.md; без них production GO запрещён.

## Где доказательства

`evidence/offline-tests.log`, `bash-n.log`, `shellcheck.log`, `systemd-verify.log`, `userspace-parser.log`, `source-checksums.log`, `validation-summary.json`, `official-sources.json`. Выходные статусы исходных команд сохранены отдельно; успешный formatter/нулевой набор тестов не подменял проверку.

Историческое исследование зависимостей v1 сохранено без подмены новой сетевой проверкой: внешний docs.amnezia.org был недоступен через proxy (403); обход не выполнялся. Использованы официальные GitHub исходники/реальный PPA package. В v2 версии/зависимости не изменялись, внешние запросы не выполнялись; неизвестное состояние действующих серверов осталось явным NO-GO, без выдуманной совместимости.

Журналы v1 (37 тестов) находятся только в evidence/v1/, помечены историческими и не доказывают состояние v2. Источник аудита Киры сохранён и имеет отдельную контрольную сумму. ZIP v1 сохранён без изменений.
