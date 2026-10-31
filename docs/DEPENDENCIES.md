# Зависимости, источники и воспроизводимость

Проверено 31.10.2026 по HTTPS с TLS verification:

| Компонент | Наблюдение |
|---|---|
| Официальный tools GitHub | `amnezia-vpn/amneziawg-tools`, HEAD/tag v3.1.20260812, commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` |
| Официальный kernel GitHub | `amnezia-vpn/amneziawg-linux-kernel-module`, HEAD/tag v3.1.20260906, commit `4569c4c67f3a57414969260cafbbd04694fbaae0` |
| PPA noble amd64 | `https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu/dists/noble/main/binary-amd64/Packages.gz` |
| tools/metapackage | `1.0.20210914-0~202608130144+ee0f0a9~ubuntu24.04.1` |
| DKMS | `1.0.0-0~202609061402+4569c4c~ubuntu24.04.1` |

Официальный README kernel описывает установку Ubuntu через `ppa:amnezia/ppa` и `apt install amneziawg`, headers текущего ядра. Автоматическая установка в комплекте ограничена новыми узлами, точными наблюдавшимися версиями и штатной APT signature verification. `full-upgrade`, reboot, отключение Secure Boot/TLS/GPG/checksum не выполняются. PPA добавляется штатным add-apt-repository; ошибка получения ключа/подписи — STOP, а не переход к trusted=yes. Непроверенные arm64/другие Ubuntu/userspace fallback не поддержаны.

Бинарник реального tools .deb скачан только в рабочую среду ревью, SHA256 совпала с HTTPS Packages: `2c924076be2ba217eea04f9693291f01c5307a9be5aeee60d04525a50ff2804f`. `awg --version` дал `amneziawg-tools v3.1.20260812 - https://amnezia.org`. Проверена поддержка парсером Jc/Jmin/Jmax/S1-S4/H1-H4. Сам .deb/чужие бинарники в deploy ZIP не включены. **APT-подпись скачанного для инспекции пакета здесь не проверялась**; это userspace-инспекция доверенного HTTPS источника, не установка драйвера или production trust attestation. При развёртывании APT обязан самостоятельно проверить подписанные метаданные и пакет.

В исходнике `linux.bash` bare interface ищется в `/etc/amnezia/amneziawg/`, хотя help упоминает `/etc/amnezia/`. Поэтому новые units используют абсолютные config paths, A блокируется без подтверждённого пути существующего unit. Нельзя выводить корректность инсталляции из текста справки.

README модуля описывает старый набор S1/S2; текущий tools parser поддерживает S3/S4 и дополнительные новые поля. Из одного README нельзя доказать поддержку старого PACO-профиля конкретным DKMS/ядром. Применение обязано создать временный down-interface `pacoprobe`, `ListenPort=0`, без адресов/маршрутов/peers сети, применить stripped config и проверить round-trip всех профилируемых параметров через kernel. Затем — настоящий межсерверный handshake и клиентский тест. Неизвестные I1-I5/HeaderProtectionKey/диапазоны H из действующего AWG1 требуют отдельного NO-GO/review; они не игнорируются.

Сайт `docs.amnezia.org/ru/documentation/amnezia-wg/` вернул proxy 403. Обход политики не выполнялся. Вместо него использованы официальные GitHub исходники и реальный PPA. Хеши/URLs/commit в `evidence/official-sources.json`; pinned исходники повторно сопоставлены с хешами загруженных файлов.

Нужны Bash 5, Python 3 (stdlib SQLite/JSON), iproute2, iptables/ip6tables-nft с save utilities, nft для обнаружения чужих tables, systemd/systemd-analyze/systemd-run, util-linux flock, kmod/modinfo, iputils-ping, ss, tar с ACL/xattr, SHA256, dpkg/APT, AWG tools/модуль текущего ядра. Базовые Python/Bash/iproute2/systemd должны присутствовать уже для preflight; установщик добавляет остальные пакеты на новом Ubuntu.

DKMS может скачивать исходники ядра: доступ к официальным Ubuntu mirrors/PPA/Launchpad/keyserver должен быть разрешён на новых VPS. Конкретный внешний отказ не лечить выключением проверки или proxy обходом. Минимум 6 GiB свободно на `/`, 4 GiB на `/tmp`, 1 GiB доступной RAM+swap, сборка ограничена `MAKEFLAGS=-jmin(2,CPU)`. Никаких фоновых дорогостоящих сборок здесь не запускалось.

Данные владельца (не входят в ZIP): исходные server/client ключи и PSK, клиентские profiles/QR, согласованный SQLite snapshot, manager source/units. Никогда не запрашивать их в чате. SSH identity/console/внешний backup подтверждает оператор; скрипт не получает секреты из connected accounts.
