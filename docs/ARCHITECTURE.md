# Архитектура и порядок загрузки

```text
IPv4 client, MTU1380, full tunnel 0/0 + ::/0 capture (IPv6 block)
  -> ENTRY UDP60333 awg0 10.77.77.1/24
  -> source CLIENT_CIDR policy pref100 table100
       default dev awg1 metric0
       unreachable default metric4278198272 (не привязан к interface)
  -> ENTRY awg1 10.88.88.1/30 UDP60334
  -> EXIT awg1 10.88.88.2/30 UDP60334
       AllowedIPs: ENTRY transit /32 + CLIENT_CIDR
       reverse CLIENT_CIDR dev awg1
  -> WAN: MASQUERADE только CLIENT_CIDR
```

Source 10.88.88.1 отдельно получает pref99 table100, как в подтверждённом PACO. Main default обслуживает хостовый SSH и внешний UDP endpoint, не изменяется. Table=off у AWG конфигов: awg-quick не создаёт другой full-tunnel policy и не трогает main default.

## Firewall

На новых узлах выбраны iptables-nft и собственный systemd guard, без UFW. Это сохраняет netfilter-функции исторического EXIT (ограниченный forward/stateful return/client-only NAT), но не переносит его UFW before.rules/широкие порты. Требование тестировать `iptables-restore --test` при UFW к данному варианту не применяется: UFW-файлы не создаются, restore не используется. Сосуществование с active UFW/native nft manager запрещено preflight.

ENTRY: первый FORWARD rule `-i awg0 ! -o awg1 -j DROP`; дополнительный исторический source-specific DROP, anti-spoof source check, точный AWG0→AWG1 ACCEPT и stateful return. Все ingress IPv4 пакеты awg0 к самому ENTRY блокируются (внешний DNS 1.1.1.1, не локальный DNS). IPv6 INPUT/FORWARD с awg0 блокируются, серверный IPv6 и SSH глобально не отключаются.

EXIT: AWG1→WAN разрешён только для CLIENT_CIDR, обратный WAN→AWG1 только RELATED,ESTABLISHED и CLIENT_CIDR. Anti-spoof/неверный выход с awg1 блокируются. MASQUERADE только CLIENT_CIDR на подтверждённом WAN, без SNAT 10.88.88.1 и без SOCKS/Dante. UDP60334 разрешён от peer public IPv4 и запрещён от остальных источников. На ENTRY peer whitelist обновляется до syncconf. Новые SSH TCP соединения на новых узлах разрешены только из проверенного IPv4 SSH_SOURCE_CIDR; существующие сессии этим правилом не обрываются. IPv6 SSH whitelist/внешняя экспозиция проверяются в provider firewall; IPv6 SSH сервера не выключается автоматически.

Общие INPUT/FORWARD policies хоста не переписываются; не закрываются неизвестные сервисы. Preflight нового узла требует отсутствия лишних интерфейсов/портов, а безопасность внешних IPv6/других host ports — отдельная подтверждённая provider policy. Это не универсальный hardening сервера.

## Systemd

`paco-deploy-guard.service` не зависит от существования AWG-интерфейсов. Он создаёт source rules/fallback/firewall и не имеет ExecStop. Для A `After=netfilter-persistent.service paco-failclosed.service`, для новых — после local-fs/netfilter-persistent, до AWG0/AWG1 и network-pre. В AWG units/drop-ins `Requires` и `After` guard. Ошибка guard блокирует запуск клиентского интерфейса.

`paco-awg1.service` на новых VPS вызывает `/usr/bin/awg-quick up /etc/amnezia/awg1.conf` явно. `ExecStartPost` добавляет table100 default (ENTRY) или обратный маршрут (EXIT); `ExecStopPost` удаляет только рабочий маршрут и сохраняет unreachable/правила/guards. На ENTRY rp_filter AWG1 устанавливается в loose=2, иначе ответы Internet через AWG1 могут отбрасываться strict reverse-path validation.

В A существующие units остаются; добавляются drop-ins на следующий boot, AWG0 не перезапускается. Новый AWG1 файл убирает старые quick hooks, вместо них persistent guard и route hooks. При нестандартной legacy функции — NO-GO до отдельного ревью. Нельзя разрешать dependency cycle удалением failclosed зависимостей.

Таймер rollback независим от AWG и имеет постоянный deadline. Live процесс не считается сохраняемым состоянием. Порядок boot проверяется сначала статически на fixtures, затем **обязательно** на реальных units обоих тестовых VPS.

## IPv6

IPv6 через EXIT в этом комплекте не маршрутизируется. Профили новых клиентов захватывают `::/0`, сервер блокирует захваченный IPv6. Криптографический peer AllowedIPs сервера остаётся IPv4-only. Native IPv6 клиента блокируется его VPN/OS политикой, что отдельно проверяется на каждой платформе. Даже идеальный серверный DROP не исправляет native IPv6 bypass вне туннеля. Если это нельзя обеспечить — --apply не разрешается.
