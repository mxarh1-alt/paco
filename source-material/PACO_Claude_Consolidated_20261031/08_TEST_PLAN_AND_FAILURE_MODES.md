# PACO — тестовый план и отказы

## Read-only перед развёртыванием
- `cat /etc/os-release`; `uname -r`; `ip -br -4 addr`; `ip -4 route show default`; `ss -lntup` (без публикации чужих данных); `awg --version`/`awg-quick` при наличии.
- Статус SSH, консоль провайдера и отдельная активная сессия; проверки внешнего firewall провайдера. Запуск `04_paco_readonly_audit.sh entry|exit`.
- Факт `53` AWG0 peer — историческая отправная точка на 31.10, не обязательное число для будущего миграционного дня.

## Проверки после настройки (не выдавать секретные ключи)
```
systemctl is-active awg-quick@awg0.service awg-quick@awg1.service paco-failclosed.service
ip -4 rule show
ip -4 route show table 100
ip -4 route get 1.1.1.1 from 10.77.77.2 iif awg0
iptables -C FORWARD -i awg0 -s 10.77.77.0/24 ! -o awg1 -j DROP
# На EXIT:
ip -4 route show 10.77.77.0/24
iptables -t nat -S POSTROUTING
ufw status verbose
# Тест связи двух AWG-интерфейсов:
ping -c 3 -W 2 -I awg1 10.88.88.2
```
Для новых подсетей использовать параметры из inventory, а не копировать примеры. `awg show ... latest-handshakes` содержит публичные ключи и timestamp; при передаче отчётов редактировать. Ненулевые счётчики сами по себе не доказывают актуальный handshake; проверять runtime и клиентский HTTPS.

## Acceptance
- Устройство клиента подключилось к ENTRY и успешно выполняет HTTPS/DNS, внешний IP совпадает с фактическим новым EXIT.
- Число и состав AWG0 peer подтверждены по сохранённому manifest, потеря клиентов не допускается в A; в B определено, кто мигрировал.
- Failclosed есть и в таблице 100, и FORWARD. При заранее согласованной контролируемой имитации отказа (с автоматическим восстановлением) не происходит выхода через WAN ENTRY. Не проводить на рабочем узле без окна обслуживания.
- На EXIT NAT и return route действуют, UFW route/conntrack разрешают нужный путь. IPv6 leak policy протестирована отдельно.
- Бэкапы лежат вне VPS, rollback воспроизводим. По одному reboot: EXIT затем ENTRY, с проверкой после каждого, без риска потери SSH.

## Отказы — локализация
| Симптом | Вероятный участок / проверка |
|---|---|
| Нет handshake AWG1 | Endpoint, UDP 60334, firewall/провайдер, ключи/AllowedIPs, параметры протокола |
| Есть handshake, нет интернета | policy table 100, forward AWG0→AWG1, return route EXIT, UFW FORWARD/conntrack, SNAT |
| Интернет идёт через ENTRY | FAIL-CLOSED нарушен; НЕМЕДЛЕННО STOP, восстановить DROP/rule/unreachable |
| Подключение нового клиента без интернета | сравнить S3/S4/MTU и параметры совместимости с работающим клиентом, handshake, DNS |
| AWG1 пропал после reboot | systemd deps и hooks, донастройка firewall persistence, startup order |
| UFW не работает после reboot | `iptables-restore --test`, before.rules syntax, apply/reload, не забывать SSH rollback |
| Статистика 0 после импорта | первый sample — база для подсчёта разницы; wait for subsequent sample, timer |
| Подключение старых клиентов B не происходит | клиентский Endpoint указывает на старый IP ENTRY; ключи/серверный public key отличаются |
| IPv6 утекает | отдельная проверка клиентской IPv6 политики, не путать с прослушиванием SSH IPv6 |
