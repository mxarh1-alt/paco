# PACO DEPLOY — комплект A и B

Подготовлен 31.10.2026. Статус: **REVIEWED STATICALLY**. Проверки на VPS, production-применение и публикация не выполнялись. Действующие серверы не опрашивались и не изменялись. Комплект предназначен для ревью Кирой, лаборатории, затем отдельного согласования оператором.

## Сначала — независимый аудит исходных данных

Основная архитектура PACO сохранена. Подтверждены IPv4-клиенты 10.77.77.0/24 → ENTRY AWG0 → AWG1 10.88.88.0/30 → EXIT с обратным маршрутом и единственным SNAT. На московском срезе подтверждены policy 99/100, unreachable fallback и FORWARD DROP, 53 peer, активный менеджер/таймер. Число 53 не зашито в алгоритм: при миграции фиксируется фактический состав.

Критические пробелы:

1. Версии AWG tools/модуля, конфиги AWG1 и содержимое legacy units отсутствуют. Нельзя доказать совместимость нового EXIT с действующей ENTRY только по наличию бинарника. Нужны профиль именно AWG1, точная версия, проверка unit и kernel round-trip. Неизвестные поля блокируют применение.
2. Серверный IPv6 DROP не предотвращает native IPv6 клиента, если клиент захватывает только `0.0.0.0/0`. Нужен подтверждённый `::/0` либо блокировка native IPv6 на каждом устройстве. При A это может конфликтовать с требованием не менять профили: если клиентская ОС не обеспечивает блокировку без нового профиля, **NO-GO**, требуется отдельное решение оператора.
3. Аудит ENTRY доказывает удаление основного маршрута и reboot, но не полный отказ AWG1 и не все IPv6-сценарии. Эти тесты ещё предстоят.
4. Полного свежего аудита старого EXIT нет. Его UFW и старые открытые порты не копируются на новые узлы. Старый EXIT сохраняется до приёмки.
5. Архивы владельца и исходник менеджера v0.2.4 в исходном ZIP отсутствуют. Полное восстановление клиентов требует исходного server private key + peer/PSK. У потерянного `client01.conf` нельзя восстановить клиентский private key из серверного peer. SQLite в tar работающей БД не является эталоном без backup API/integrity_check.

Подробности: [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md), [docs/CLAUDE_REVIEW.md](docs/CLAUDE_REVIEW.md).

## Поддерживаемый вариант

Новые VPS: **Ubuntu 24.04, amd64**, одинаковый точный `PRETTY_NAME` в B, ядро каждого узла указывается после аудита. Только kernel AmneziaWG, **iptables-nft с собственным `paco-deploy-guard.service`**. Это явный выбор для новых VPS; исторический EXIT с UFW не перенастраивается. На существующей ENTRY A продолжается работа netfilter-persistent; guard загружается после него и legacy failclosed, до AWG0/AWG1.

Активный UFW/firewalld/nftables manager, неизвестные native nft tables, legacy rules параллельно nft, Secure Boot без подтверждённой подписи модуля, provider NAT вместо адреса на WAN, конфликтующие сети/порты/правила — **NO-GO**. Автоматической смены backend нет. Для UFW-варианта требуется отдельный рассмотренный комплект; данный код не меняет `before.rules` и не вызывает `ufw reload`.

Проверены официальные исходники и реальный userspace-пакет; см. [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md). На новом VPS установка идёт через подписанный APT PPA с точными версиями. Если этих версий больше нет, установка останавливается; нельзя заменять версии/хеши без повторного ревью. Проверка парсера здесь не заменяет DKMS/handshake на реальном ядре.

## Что входит

- `scenario-A/`: новый EXIT → застрахованное переключение ENTRY → verify/commit → rollback.
- `scenario-B/`: новый EXIT → ENTRY с guard → transit → restore/enroll → verify/commit.
- `common/`: preflight, локальные ключи, установка AWG на новых узлах, backup, verify, rollback; общая Bash-реализация и Python 3 для безопасного разбора конфигов/SQLite.
- `config/`: только несекретные примеры inventory, профиля и операторских свидетельств. Значения `TO_FILL`/`TO_CONFIRM` никогда не используются как работающая конфигурация.
- `tests/`: offline-тесты, static units check, согласуемый fault drill и acceptance checklist.
- `source-material/`: неизменённые исходные документы с исходным SHA256SUMS, для трассировки.

## Подготовка оператором

Следующие команды — инструкции для будущего согласованного окна. Автор их на VPS не выполнял.

1. Проверить `SHA256SUMS.txt` в корне распакованного ZIP. Хеши фиксируют целостность, но не заменяют доверие к источнику архива.
2. Скопировать комплект на соответствующий узел в защищённый каталог, например `/root/PACO-DEPLOY`. Владелец всех файлов/родительских каталогов — root, без записи другим пользователям; не запускать root-код из доступного на запись каталога. Все секретные файлы — 0600, каталоги секретов — 0700.
3. Подготовить `/root/paco/config.env`, отдельный `/root/paco/inventory.env` на КАЖДОМ узле; chmod 0600. Inventory переопределяет общие поля. `NODE_ROLE`, SSH whitelist и hostname относятся к этому конкретному узлу. Значения пишутся буквально, shell-подстановки запрещены.
4. Проверить provider console, открыть второй SSH, фактический SSH whitelist/provider firewall, внешний backup и возможность его чтения. Флаги подтверждения — свидетельство оператора, скрипт не умеет самостоятельно доказать доступность консоли.
5. Заполнить клиентское IPv6 evidence только по реальному тесту, `reviewed_at_epoch` не старше 24 часов. В A проверить каждую используемую клиентскую платформу/политику. Не ставить `YES` ради обхода проверки.
6. Сначала прочитать и выполнить лабораторный [runbook A](docs/RUNBOOK_A.md) или [runbook B](docs/RUNBOOK_B.md). Каждый узел использует свой локальный inventory. Никаких автоматических SSH/SCP/HTTP команд к рабочим VPS в комплекте нет.

Предпросмотр (не пишет файлы, не создаёт ключи/interfaces, не устанавливает пакеты):

```bash
bash scenario-A/02-stage-and-switch-entry.sh \
  --config /root/paco/config.env --inventory /root/paco/inventory.env --dry-run
```

Он выполняет только read-only preflight и завершится `NO-GO` вне нужного VPS/при неизвестных полях. Успех preview не означает готовности production.

Пример явного разрешения конкретного этапа, только после ревью и лаборатории:

```bash
bash scenario-A/02-stage-and-switch-entry.sh \
  --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --apply --confirm 'APPLY A-switch-entry' \
  --console-confirmed --second-session-confirmed --entry-cutover-approved
```

Каждый wrapper печатает план и принимает `--help`. Для других этапов точная строка подтверждения указана в runbook/плане. Смешивание `--dry-run` и `--apply` запрещено. Повторный setup при active транзакции блокируется: это безопасная идемпотентность, а не повторное добавление правил. `B-clients` может продолжить pending `B-setup-entry` без продления исходного deadline.

## Граница автоматизации и commit

Скрипты **не перезагружают серверы**. Подготовленный systemd rollback timer использует абсолютный UTC deadline и `Persistent=true`: после reboot он продолжает страховать тот же deadline. Оставьте достаточно времени (`ROLLBACK_SECONDS` 300..3600); если время истекло, сначала установить результат rollback, потом заново планировать работу. Не снимайте timer вручную для обхода acceptance.

`verify` проверяет реальный локальный маршрут, правила, NAT/return route, свежий handshake и transit ping. `commit` дополнительно требует свежий root-only `acceptance.json`: клиентский внешний IP, DNS/HTTPS, оба fault-теста, IPv6, внешний backup, новый SSH и ручной reboot EXIT → ENTRY. Это операторская аттестация, а не удалённое измерение скриптом; поля нельзя заполнять по предположению. Commit выполнить на обоих узлах.

Автоматическая активация неизвестного менеджера B исключена: `RESTORE_OFFLINE` сохраняет исходник и согласованную SQLite в quarantine, ничего не запускает и не сбрасывает историю. Адаптация `ENDPOINT/NET`, проверка v0.2.4 и units — отдельный **NO-GO до получения и локального аудита исходника**. Клиентский VPN при этом работает без менеджера; `MANAGER_MODE=NONE` — допустимый явный выбор.

## Аварийный откат

На том же узле по ID из `ROLLBACK ARMED`, без зависимости от исправности AWG/inventory:

```bash
bash common/rollback.sh --snapshot ID --dry-run
bash common/rollback.sh --snapshot ID --apply --confirm 'APPLY rollback'
```

Замените `ID` реальным ID. Возвращается только текущая active транзакция. Не применяется слепой глобальный firewall restore/flush и не меняется main default. На B AWG0 может быть остановлен, но конфиг/ключи/профили остаются; клиенты автоматически не удаляются. Полный порядок: [docs/ROLLBACK.md](docs/ROLLBACK.md).

## Повторить локальные проверки без VPS

```bash
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_offline.py
python3 tests/check_units.py
find . -name '*.sh' -print0 | xargs -0 -n1 bash -n
# Если shellcheck установлен:
find . -name '*.sh' -print0 | xargs -0 shellcheck -x -P SCRIPTDIR -S style
```

Фактические результаты и их пределы: [tests/test-results.md](tests/test-results.md). Переходы **REVIEWED STATICALLY → TESTED IN LAB → PRODUCTION-APPROVED** требуют отдельных доказательств и согласия оператора.
