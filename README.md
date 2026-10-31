# PACO-DEPLOY v2

Полный комплект для двух сценариев: **A — замена только EXIT**, **B — два новых VPS**. Версия 2.0.0 исправляет подтверждённые проблемы из независимого аудита Киры.

## Скачать

- **[Готовый ZIP PACO v2](https://github.com/mxarh1-alt/paco/raw/refs/heads/main/downloads/PACO-DEPLOY_v2_20261031.zip)**
- [SHA256 v2](downloads/PACO-DEPLOY_v2_20261031.zip.sha256)
- [Предыдущий ZIP v1](downloads/PACO-DEPLOY_20261031.zip), сохранён без изменений.
- Весь репозиторий: **Code → Download ZIP**.

Начните с [README_RU.md](README_RU.md). [Краткий список исправлений](CHANGELOG_V2.md), [ответ на все пункты аудита Киры](docs/KIRA_RESPONSE.md), [результаты тестов](tests/test-results.md).

## Исправления v2

- Разделены A/new-node guard units: убран потенциальный цикл network-pre ↔ online/legacy для существующей ENTRY; защита до AWG0 сохранена.
- Восстановление AWG0 сохраняет имена и комментарии peers.
- Добавлена проверка будущего A графа на конкретном хосте до cutover; точные ExecStart/ExecStop пути AWG1, без shell wrappers/частичных совпадений.
- Manager B остаётся в offline quarantine: его код не исполняется и collector не активируется.

**Проверено локально:** 51 тест, 0 пропусков, bash -n, ShellCheck, 5 моделей systemd (3 положительных и 2 ожидаемых отказа). Статус REVIEWED STATICALLY. На реальных VPS граф/handshake/NAT/IPv6/SSH/rollback/reboot не проверялись; действующие серверы не изменялись.

По умолчанию скрипты работают в dry-run. Неизвестные inventory/AWG/IPv6 условия блокируются NO-GO. Нужны лаборатория, ревью и отдельное согласие оператора перед применением. Рабочих private keys/PSK в комплекте нет.
