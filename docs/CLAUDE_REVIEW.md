# Итог ревью комплекта PACO

Подготовлено по 01_CLAUDE_MASTER_TASK.md и всему консолидированному архиву от 31.10.2026. Исходные 13 файлов прошли проверку исходного SHA256SUMS. Рабочие серверы не опрашивались, изменения не выполнялись. Репозиторий `/workspace/paco` оставлен без исходников/коммитов; результат поставляется отдельным ZIP.

## Соответствие поставки

Все запрошенные публичные Bash-файлы common/scenario-A/scenario-B присутствуют. Реальные алгоритмы находятся в `common/engine.sh`, общие функции — `lib.sh`, безопасная обработка конфигов/SQLite/undo — `data.py`, read-only preflight/verify — `checks.py`. Это обычные Bash scripts с Python stdlib helper, не pseudocode. В config только обязательные неизвестные inventory и пути локальных секретов; для основных операций TODO нет.

Дополнительно: installer, key-generation wrapper, actual boot hooks/callback, fault drill, конкретные runbooks A/B/rollback, зависимости/official evidence, acceptance examples и локальные тесты. Systemd units/drop-ins/timer генерируются из проверенных heredocs; `templates/*.in` — их экспорт для ревью, не отдельная точка настройки. `tests/check_units.py` проверяет именно heredocs исполняемого генератора, а не только копии templates.

## Существенные решения

1. На новых узлах выбран iptables-nft с own persistent guard. Исторический UFW EXIT не копируется и не меняется. Нативный nft/UFW конфликт — STOP.
2. Никаких guessed WAN/IP/AWG1 parameters. AWG0 client profile подтверждён исходным комплектом; transit profile A должен быть извлечён с реального AWG1, B использует проверяемый кандидат.
3. Независимый failclosed и безопасный boot предшествуют AWG0. A не перезапускает AWG0 и не переписывает manager/SQLite. Legacy несовместимость блокирует A, не исправляется скрытно.
4. Перенос B сохраняет server private key и peer/PSK; Endpoint нового ENTRY обновляет владелец на клиентах. Reissue даёт новые private profiles только локально.
5. Клиентский native IPv6 невозможно блокировать сервером, если он идёт мимо туннеля. Поэтому отсутствие платформенного evidence блокирует применение, даже если IPv6 FORWARD DROP уже есть.
6. Manager B может быть восстановлен только offline с целостной SQLite; marker версии/AST public settings проверяются, код/units не исполняются. Полное включение неизвестного исходника не выдумывается.

## Что ещё должен сделать оператор

Получить фактическую inventory новых узлов, AWG1 profile/version/unit A, provider firewall/консоль/SSH evidence, private backups у владельца. Выполнить лабораторный deploy/rollback/failures/reboot, сверить клиентскую политику IPv6 и текущий EXIT IP, затем ревью Кирой. Только после этого согласовать production window. `tests/test-results.md` отделяет выполненные проверки от неисполненных.

| Ступень | Статус |
|---|---|
| REVIEWED STATICALLY | Выполнено локально; ограничения перечислены |
| TESTED IN LAB | Не выполнено: тестовых VPS/фактических inventory в запросе нет |
| PRODUCTION-APPROVED | Нет: разрешение выдаёт оператор после лаборатории |

В пакет не включены private keys, PSK, tokens, исходные client secrets/SQLite либо чужие бинарники. Не применять ZIP как слепой one-click installer к рабочей инфраструктуре.
