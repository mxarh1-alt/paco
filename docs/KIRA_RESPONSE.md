# Ответ на независимый аудит Киры

Источник: `source-material/PACO_KIRA_AUDIT_AND_RUNBOOK_20261031.md`, сохранён без изменений. Этот ответ относится к v2.0.0. Два P1 подтверждены; по перечисленным ограничениям разногласий нет.

| Замечание | Проверка | Решение v2 |
|---|---|---|
| A guard After legacy, Before network-pre | Модель с legacy After network-online и обычным порядком network manager воспроизводит ordering cycle v1 | Раздельные A/new-node templates; A после online/legacy, до AWG0/1, без Before network-pre. Requires+After guard на AWG0/1 сохранены |
| Слабые v1 fixtures | В v1 legacy и online targets не образовывали настоящую сетевую цепочку | Модель включает network-pre→networkd→network.target→wait-online→online→legacy; negative control старого кода обязан быть отвергнут. Ещё один negative control моделирует legacy After AWG1, который по-прежнему NO-GO |
| Потеря `# galt`, `# testpaco` | Старый parser удалял # до восстановления, render их не возвращал | Section metadata хранит комментарии до/внутри [Peer], inline/header notes и порядок. Regression сравнивает соответствие тех же ключей/IPv4, private key и повторный parse/render |
| Абсолютный ExecStart A | Фактический unit Москвы полностью не представлен | Проверка не снята, а уточнена: точные argv up/down для ExecStart/ExecStop, без частичного совпадения .conf.bak и без shell wrapper. Нельзя предполагать поиск bare awg1/делать symlink/переписывать unit без локального аудита; NO-GO остаётся |
| AWG версия/profile/PSK неизвестны | Новых фактов о действующей Москве нет | Точные profile/version/PSK и новые WAN/IP не выдуманы; module probe и handshake в лаборатории обязательны. Неизвестные peer-поля AWG1 дополнительно блокируются |
| IPv6 native bypass клиента | Сервер не контролирует трафик, который вообще не вошёл в туннель | Захват ::/0 или OS block + platform test/evidence обязательны; server DROP не выдаётся за решение client bypass |
| Manager/collector только offline | Источник v0.2.4 и приватные backups не приложены | Сохранён RESTORE_OFFLINE: SQLite API backup/integrity check, source quarantine, AST-only public settings report; activation_allowed=false. Source-код не исполняется, timer не включается. Полноценная активация не заявляется |
| Новый ENTRY IP меняет endpoint | Server private key не сохраняет внешний адрес | Endpoint обновляет оператор на устройствах; DNS/сохранение прежнего адреса требуют отдельного проекта и проверки, автоматически не обещаны |
| client01 без private profile | PublicKey и server peer не раскрывают client private key | Peer/имя сохраняются, недостающий private profile не создаётся под прежней идентичностью |
| Timer не гарантирует rollback | Возможны отказ systemd/диска/SSH, истечение окна и частичный обратный журнал | Console/второй SSH/внешний backup, контроль deadline и состояния сохранены. Нет заявления об успешном rollback до фактической проверки |
| Нет реальных сетевых/reboot испытаний | На VPS не обращались | Все такие пункты UNRUN; статус остаётся REVIEWED STATICALLY, production NO-GO до лаборатории и согласия оператора |

## Как проверяется исправленный systemd граф

1. Offline test читает именно активные templates и генератор heredocs, а не вручную нарисованный правильный unit. Проверяет три положительных модели и две отрицательные. Это лучше v1 fixtures, но всё ещё модель.
2. В будущей согласованной A apply `units.py stage-a` сохраняет точные prospective guard/drop-ins в защищённый каталог. До изменения активных файлов/firewall `verify-live-a` использует настоящие `/etc/systemd/system`, `/run/systemd/system`, runtime generator directories и vendor unit files конкретного хоста. Главные units AWG0/AWG1/legacy/netfilter проверяются вместе. Никаких systemctl start/reload эта функция не вызывает.
3. Ещё не установленный runtime executable заменён в проверочном overlay на тот же исходник KIT; ordering [Unit] и зависимости не меняются. Canonical staged files не переписываются и именно они затем устанавливаются. После установки идёт verify с конечным runtime path.
4. Любая ошибка или диагностированный cycle даже при exit 0 — NO-GO. Вывод host units не публикуется в логах, чтобы не раскрыть возможные чужие приватные Environment/argv. Оператор разбирает локальные unit-файлы отдельно.
5. Это проверка статических файлов конкретного хоста, не доказательство реальной загрузки/сетевой работы. Reboot EXIT→ENTRY и AWG1 startup failure обязательно испытываются в лаборатории. Возможные дополнительные legacy зависимости не угадываются и автоматически не удаляются.

## Имена и менеджер — разные уровни

Сохранение имён в AWG0 исправляет подтверждённую потерю данных. Оно не активирует старый менеджер и не доказывает, что любая неизвестная версия manager parser принимает все возможные варианты комментариев. Восстановленный текст сохраняет имена в исходном окружении public key/IPv4; у владельца остаются private client files и SQLite history. Без имени в исходнике комплект не угадывает его из IP. Дублирующий public key блокируется, а не сливается молча.

Source manager AST marker `0.2.4`, ENDPOINT/INTERFACE/NET и SQLite integrity — полезные проверки, но не экспертиза произвольного кода/units/SQLite schema/migrations. Поэтому v2 не выдаёт их за разрешение запустить collector. После отдельного получения исходника владельцем потребуется сверка names/peers/IPv4 с SQLite и profiles, проверка endpoint и запуск/первые samples в лаборатории. В A manager остаётся неизменным.

## Разница результатов v1 у Киры и Клары

35 PASS + 2 skipped у Киры и 37 PASS в исходной рабочей среде не противоречат друг другу: root-gate test пропускается при запуске тестов root, optional pubkey test — без проверенного AWG binary. В v2 отчёт указывает реальные выполненные/пропущенные counts и среду; отсутствие ShellCheck у другого проверяющего не превращается в независимый PASS. v1 журналы оставлены в evidence/v1 только как история, текущие результаты — evidence/.
