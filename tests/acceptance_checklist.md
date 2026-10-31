# PACO v2: приёмка GO / NO-GO и отказы

Не выполнялась на VPS при подготовке ZIP. Начинать с лаборатории, отдельного согласия и console/двух SSH. Никакая отметка ниже не должна ставиться по одному открытому порту/PID/ненулевому счётчику.

## До изменений

- [ ] Проверена целостность ZIP и исходного комплекта, проведено ревью Кирой.
- [ ] Реальные inventory: роль/hostname, точный Ubuntu24.04 amd64, kernel, публичный IPv4 на подтверждённом WAN, provider policy/SSH whitelist.
- [ ] Порт SSH слушается, вторая сессия открывается из разрешённого источника; provider console реально открыта.
- [ ] Нет UFW/firewalld/native nft/legacy conflicts; на новых узлах нет enabled конкурирующих units, лишних interfaces/сервисов/VPN.
- [ ] CLIENT_CIDR/TRANSIT_CIDR не пересекаются с другими интерфейсами/маршрутами; table100 и pref99/100 свободны либо ровно PACO.
- [ ] AWG package/tool/module kernel соответствуют, transit profile фактический; в A файл/private key AWG1 соответствует runtime public key и путь unit известен.
- [ ] В A исходные rule/unreachable/DROP и persistent units подтверждены, AWG0 file/runtime peers согласованы, hooks/unit dependency graph рассмотрены. eth1 не затрагивается.
- [ ] Подтверждено для каждого типа клиента: `::/0` действительно захватывается либо OS блокирует native IPv6; не отключается глобальный IPv6 сервера.
- [ ] Внешний backup доступен и читается; для новых VPS есть внешний snapshot до установки APT/DKMS. Для SQLite есть API copy+integrity_check, не только tar.

## После каждого этапа

- [ ] Прочитан план, --apply и точный confirm даны для правильного узла; отдельно разрешён A cutover.
- [ ] На опасном этапе появился timestamp backup, active transaction ID и **active** persistent timer с будущим deadline.
- [ ] Kernel pacoprobe проверил round-trip J/S/H и удалён; AWG0/awg1 и чужие interfaces не удалялись.
- [ ] Исправленные A templates не содержат Before=network-pre; staged verify проверил фактические host units перед cutover (не fixtures), а New-node guard не зависит от legacy failclosed.
- [ ] Systemd units проверены на реальном VPS (статические fixtures недостаточны); guard без зависимости от интерфейсов и без ExecStop, AWG0 требует успешный guard.
- [ ] `paco-deploy-guard.service`, нужные AWG units enabled/active, нет связанных failed units. A manager/statistics timer не затронуты.
- [ ] ENTRY main default и eth1 неизменны; table100 рабочий default dev awg1 и unreachable default metric4278198272. Никакого ENTRY SNAT.
- [ ] EXIT reverse CLIENT_CIDR dev awg1, правильные forward/stateful return, NAT только CLIENT_CIDR→WAN; нет awg0.
- [ ] Входящий UDP60334 IPv4 только от противоположного узла; IPv6 UDP60334 заблокирован.

Для диагностики оператор локально сравнивает:

```bash
ip -4 rule show
ip -4 route show table 100
ip -4 route show default
ip -4 route get 1.1.1.1 from 10.77.77.54 iif awg0
iptables -S FORWARD
iptables -t nat -S POSTROUTING
ip6tables -S FORWARD
```

Заменить адрес клиента на реальный TEST_CLIENT_IP из inventory (в новом B он часто .2). Не публиковать весь config/showconf/dump. Для report достаточно статуса проверок, fingerprint/count, timestamps, без ключей.

## Нормальный полный каскад

- [ ] `common/verify.sh --config ... --inventory ... --dry-run` прошёл на обоих узлах. ENTRY route get вернул awg1/table100, EXIT обратный маршрут/SNAT присутствуют, ожидаемый sole-peer handshake не старше 180s, transit ping прошёл.
- [ ] Тестовый клиент подключился к AWG0. С него `curl -4 --fail --max-time 15 https://api.ipify.org` возвращает **актуальный новый EXIT IPv4** из inventory. Команда только для оператора на клиенте; автор ZIP её против VPS не выполнял.
- [ ] DNS (`getent ahostsv4 example.org` на поддерживающем Linux клиенте либо штатная DNS-проверка устройства), обычный HTTPS, крупный transfer/MTU работают. DNS не уходит по native bypass согласно проверке платформы.
- [ ] IPv6 request с клиента (например `curl -6 --fail --max-time 10 https://api64.ipify.org`) не имеет выхода. Ошибку одного сервиса нельзя считать доказательством: подтвердить capture ::/0/OS block, локальные маршруты и несколько доступных контрольных IPv6 destinations.
- [ ] В A исходный AWG0 checksum/runtime peer set и manager source неизменны; действующие клиенты не требуют нового профиля. Не считать обязательным старое число 53, использовать сохранённый manifest текущего окна.
- [ ] В B имена/комментарии peers из backup присутствуют в восстановленном AWG0 и соответствуют тому же PublicKey/IPv4; новый peer имеет своё # имя.
- [ ] В B восстановлены нужные server/client identities либо выданы новые profiles. Новый Endpoint применён на устройствах. Потерянный private profile не «восстановлен» из публичного peer.

## Согласованные fault drill

На ENTRY внутри active застрахованной транзакции, заранее запустить непрерывные внешние IPv4/IPv6/DNS проверки с тестового клиента и при необходимости metadata-only capture WAN. Не инициировать на production без окна. Callback восстановления через 45s вооружается **до** отказа; после внутренних проверок выдерживается 10s для наблюдения, затем немедленное восстановление. Старый основной rollback timer остаётся.

```bash
bash tests/failclosed-drill.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --fault route --apply --confirm 'APPLY failclosed-drill' --console-confirmed --second-session-confirmed
bash tests/failclosed-drill.sh --config /root/paco/config.env --inventory /root/paco/inventory.env \
  --fault awg1 --apply --confirm 'APPLY failclosed-drill' --console-confirmed --second-session-confirmed
```

- [ ] При потере только table100 рабочего default: route get от CLIENT_IP/iif awg0 — No route to host/Network is unreachable, первый независимый DROP на месте; клиент не выходит через ENTRY/native network.
- [ ] При полном stop AWG1 unit: source rules/unreachable/IPv4 и IPv6 DROP сохраняются; AWG0 не перезапускается. Клиент не имеет обхода через ENTRY WAN. После восстановления handshake и обычный выход снова через EXIT.
- [ ] Отдельно в лаборатории: некорректный endpoint/недоступный EXIT, неуспешный startup AWG1, отсутствие AWG0 при запуске guard, загрузка после reboot. Ожидается потеря клиентской связи, а не fallback в main.
- [ ] Проверен timed rollback и ручной rollback с сохранением AWG0 identities/manager/SSH. Результат подтверждён по состоянию, не только по срабатыванию timer. Checkpoint повторного rollback не повторяет успешные destructive inverses.

## Reboot и commit

- [ ] Ручной reboot EXIT, затем SSH/units/route/NAT/client-проверка, timer/deadline проверен.
- [ ] Ручной reboot ENTRY, затем guard/rules/fallback, AWG0/AWG1/manager, handshake/клиентский IPv4/DNS/IPv6. Никакого автоматического reboot из комплекта.
- [ ] После reboot записаны текущие boot IDs: `cat /proc/sys/kernel/random/boot_id` на каждом узле.
- [ ] Fingerprint/count на ENTRY: `python3 common/data.py fingerprint /etc/amnezia/awg0.conf` (это digest, не private data).
- [ ] Фактические результаты внесены в root-only acceptance.json; `checked_at_epoch` (`date +%s`) <=30min, на каждом узле локальный boot_id совпадает. `observed_exit_ip` измерен на клиенте, а не заполнен копированием inventory.
- [ ] Verify+commit прошли на ОБОИХ узлах, active marker отсутствует, соответствующие timers inactive/disabled; внешний backup финального состояния забран и сверен.
- [ ] Старый EXIT A сохранён до общего GO; его демонтаж вне этих скриптов и требует отдельного согласия.

## Локализация отказов

| Симптом | Проверка / решение |
|---|---|
| Нет handshake | Public keys/PSK, фактические J/S/H, endpoint IPv4/UDP whitelist, provider firewall, модуль/MTU; не выдавать старые счётчики за свежий handshake |
| Handshake есть, интернета нет | table100/pref100/default/fallback, forward counters, EXIT return route, SNAT только client CIDR, rp_filter AWG1=2, DNS/MTU |
| Клиент вышел через ENTRY | Немедленно NO-GO, сохранить независимый DROP/rules/unreachable; rollback в согласованное состояние, выяснить чужой policy/NAT/ранний ACCEPT |
| IPv6 обходит VPN | Клиентский ::/0/OS block, не подменять проверку отключением IPv6/SSH сервера |
| AWG1 не стартует после boot | Explicit config path, DKMS текущего ядра, unit graph/route hook; guard должен остаться до AWG0 |
| Недоступен SSH | Provider console, известный SSH_SOURCE_CIDR/порт, статус собственного rollback timer; не flush весь firewall |
| Manager B содержит старый Endpoint | Оставить quarantine, не включать timer; отдельный аудит/адаптация ENDPOINT/INTERFACE/NET и копии SQLite |
| SQLite statistics 0 | Проверить исходные daily/counters/peers и subsequent sample; не сбрасывать БД. В offline режиме работа timer не заявляется |

Любой неизвестный обязательный результат — **NO-GO**, не заполнять acceptance как PASS и не снимать страховку.
