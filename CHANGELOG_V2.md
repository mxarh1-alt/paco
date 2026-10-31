# PACO-DEPLOY v2.0.0 — изменения от 31.10.2026

Полный комплект, оба сценария A/B сохранены. v1 не применяется как основа без этих исправлений. Действующие VPS не опрашивались и не изменялись, приватные ключи не запрашивались.

## Исправлено

1. **P1 / systemd A:** отдельный guard для существующей ENTRY после network-online/netfilter-persistent/legacy failclosed и до AWG0/AWG1. Удалена связь Before=network-pre для A. На новых узлах сохранён отдельный ранний guard без legacy-зависимости. Requires+After AWG0→guard и отсутствие ExecStop сохраняют fail-closed.
2. **Проверка будущих A units:** до активных файлов/firewall staged guard/drop-ins проверяются с реальными unit-файлами хоста через standalone systemd-analyze. Для ещё не установленного helper меняется только executable path на тот же исходник, [Unit] и зависимости остаются точными. Ошибка/cycle/timeout блокируют cutover; после установки — повторная проверка с конечным путём. Эта процедура добавлена в код, на реальном VPS пока не выполнялась.
3. **P1 / имена B restore:** сохраняются `# имя` до [Peer] и внутри секции, inline/Unicode/прочие комментарии. Метаданные отделены от AWG fields, в kernel stripped config не попадают. Новые peers тоже получают `# имя`. При удалении SaveConfig не теряются его заметки.
4. **Целостность restore:** повторный PublicKey с другим IP отвергается, чтобы импорт не создал неоднозначное имя/ключ/адрес. Серверный private key, PSK, AllowedIPs и порядок peers сохраняются; новые идентичности не подставляются.
5. **A AWG1:** неизвестные peer-параметры теперь явно блокируют переписывание, а не теряются. ExecStart/ExecStop проверяются как прямые команды awg-quick up/down с точным путём: `.conf.bak`, bare awg1, shell wrapper и дополнительные команды не принимаются по совпавшей подстроке. Версия/profile/PSK, legacy hooks и отдельное согласие cutover остаются строгими.
6. **Manager B:** report прямо содержит `activation_allowed=false` и перечень отсутствующих статических настроек. Тест подтверждает, что анализ исходника не выполняет его код. `RESTORE_OFFLINE` не превращён в скрытую установку/активацию менеджера или collector.

## Проверки

Повторены offline unit/regression, bash -n, ShellCheck, userspace AWG parser и systemd-анализ расширенных моделей. Модель воспроизводит ошибку v1 и отвергает дополнительный ошибочный legacy-ordering; новый A и ранний new-node guard проходят. Точные counts/exit codes — [tests/test-results.md](tests/test-results.md), журналы — evidence/.

## Ограничения сохранены

Нет реальных VPS/handshake/NAT/client IPv6/SSH/rollback/reboot tests. Версии и точный AWG1 profile Москвы, новые inventory и client IPv6 policy требуют локального подтверждения. Новый ENTRY IP требует обновить Endpoint клиентов; потерянный private profile client01 не восстанавливается из public peer. Менеджер v0.2.4/SQLite collector активируется только отдельной рассмотренной процедурой после получения исходника владельцем локально, не в чате.

По аудиту Киры разногласий нет: два P1 приняты; остальные перечисленные пункты — верные ограничения, а не разрешение их обходить. Подробно: [docs/KIRA_RESPONSE.md](docs/KIRA_RESPONSE.md).
