# PACO — эталонная фактическая схема (по сообщениям оператора, 30–31.10.2026)

## Сводка
```
AWG-клиенты (53 peer, IPv4 10.77.77.0/24)
  └── UDP/60333 → Москва ENTRY (217.199.252.90)
        awg0 10.77.77.1/24
        policy routing table 100 + firewall fail-closed
        awg1 10.88.88.1/30 UDP/60334
             ⇄ EXIT Алматы (72.56.2.102)
                 awg1 10.88.88.2/30
                 return 10.77.77.0/24 dev awg1
                 UFW FORWARD + MASQUERADE o eth0
                 → Интернет (внешний IP 72.56.2.102)
```

## ENTRY — Москва: подтверждённые параметры
- Хост: `msk-1-vm-9d6q`; Ubuntu **24.04.5 LTS**, kernel `6.8.0-147-generic` по read-only аудиту от 31.10; внешний IPv4 `217.199.252.90` на `eth0`; ещё `eth1=10.200.200.4/24` — **назначение eth1 неизвестно, не трогать без выяснения**.
- Default route основного хоста: два совпадающих next-hop `217.199.252.1` через eth0 (один static/onlink, второй DHCP metric 100). **Не чистить автоматически**.
- `/etc/amnezia/awg0.conf`: 53 peer, awg0=10.77.77.1/24, UDP 60333, клиентские IP 10.77.77.2...54; 52 клиентских файла в `/root/awg-client/`, отсутствует только `client01.conf` (peer 10.77.77.2); `testpaco` 10.77.77.54 рабочий, `pacocheck` 10.77.77.55 ранее удалён с сервера, его конфигурационный файл и QR могли остаться.
- `/etc/amnezia/awg1.conf`: awg1=10.88.88.1/30, UDP 60334, endpoint EXIT текущий по состоянию; точно подтверждённые runtime правила после reboot:
```
0: from all lookup local
99: from 10.88.88.1 lookup 100
100: from 10.77.77.0/24 lookup 100
32766: from all lookup main
32767: from all lookup default

# table 100:
default dev awg1 scope link
unreachable default metric 4278198272
```
- Firewall (iptables, persisted with `netfilter-persistent`): `-A FORWARD -s 10.77.77.0/24 -i awg0 ! -o awg1 -j DROP`. На проверке `iptables -C ...` вернул 0. Входящий UDP 60334 от актуального EXIT требовал whitelist. УФВ `ufw` binary отсутствовал при аудите; старый unit `ufw.service` отображался `enabled / inactive` — **не считать UFW действующим firewall ENTRY**.
- `paco-failclosed.service`: enabled+active, таблица и правило устойчиво сохранились после reboot; `awg-quick@awg0.service` и `awg-quick@awg1.service` enabled+active. `netfilter-persistent.service` enabled+active.
- IPv4 `net.ipv4.ip_forward=1`. AWG0 сервер не должен делать локальный NAT в WAN; NAT только EXIT.
- SSH TCP/22 слушал IPv4 и IPv6 по проверке 30.10, но **внешняя IPv6-доступность и текущий SSH whitelist не зафиксированы в свежем аудите**. До любых firewall изменений проверить.

## EXIT — Алматы: подтверждённые ранее параметры
- Хост `ala-1-vm-3lss`, прежний публичный IPv4 `72.56.2.102`, WAN `eth0`.
- awg1 10.88.88.2/30, UDP 60334, peer ENTRY; в AllowedIPs включены 10.88.88.1/32 и клиентская сеть 10.77.77.0/24. EXIT не должен содержать активный awg0, захватывающий 10.77.77.0/24.
- `10.77.77.0/24 dev awg1 scope link` восстановился после reboot, `iptables -t nat -S POSTROUTING` содержал `-s 10.77.77.0/24 -o eth0 -j MASQUERADE`, UFW `active`, route allow `from 10.77.77.0/24 in awg1 out eth0`, возврат через stateful RELATED,ESTABLISHED в before-forward.
- UDP 60334/udp во входящем UFW разрешён только из `217.199.252.90` (ENTRY). Исторически другие порты 60333/udp, 8888/tcp, 8080/tcp и SSH имели широкие правила — **нужно отдельно ревизовать, не отменять вслепую**.
- После перезагрузки EXIT 30.10 в `13:51:54 UTC` AWG1/UFW active, маршрут и NAT на месте, systemd 0 failed; Москва пинговала 10.88.88.2 3/3 с ~49 мс.

## Проверки в реальной установке
- С телефона/клиента увиден внешний IP `72.56.2.102` (Алматы).
- При временном удалении `default dev awg1 table 100` оставался `unreachable default metric 4278198272`, `ip route get 1.1.1.1 from 10.77.77.2 iif awg0` → **`RTNETLINK answers: No route to host`**; после восстановления маршрут снова через awg1. Отдельно работает независимый DROP в FORWARD.
- Перезагружены EXIT и затем ENTRY, каскад восстановился. ENTRY boot `2026-10-30 13:55:02 UTC`; 4 службы были active: `paco-failclosed`, `awg-quick@awg0`, `awg-quick@awg1`, `netfilter-persistent`.
- Клиентский `testpaco` с 10.77.77.54 работал после исправления параметров `MTU=1380`, `S3=12`, `S4=12`. Генератор PACO AWG Manager v0.2.4 уже выдаёт эти параметры. Создание `pacocheck` с 10.77.77.55 и затем удаление его peer проверены на живом сервере: количество 54 → 53, AWG0 и AWG1 и timer остались active.

## Не проверено / не выводить как факт
- Полный аварийный тест остановки/падения сервиса AWG1 с наблюдением реального внешнего трафика; отдельно проверялось **удаление основного маршрута** и реальный reboot.
- Гарантия отсутствия IPv6-утечки при всех состояниях; нужна проверка политики клиентского IPv6.
- Версии AWG бинарников/драйверов на обоих узлах не представлены.
- Свежий read-only отчёт EXIT после всех последних клиентских операций отсутствует.
- Согласованность восстановленного SQLite архива не проверялась путём реального восстановления (целостность действующей БД `PRAGMA quick_check=ok`).
- Нельзя утверждать, что старый выходной VPS автоматически доступен после его замены или что новые публичные IP/маршруты известны.
- Dante/SOCKS5: исключён из комплекта; прокси был запущен, но выход через него не работал — не использовать как критерий готовности каскада.
