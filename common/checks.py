#!/usr/bin/env python3
"""Read-only preflight и проверки. Ничего не публикует из приватных конфигов."""
import hashlib
import ipaddress as ip
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
from data import (validate, envfiles, fail, pubkey, profile, secure_file, parse_awg,
                  TOOLS_PACKAGE, DKMS_PACKAGE)

def run(*args, ok=True):
    p=subprocess.run(args,text=True,capture_output=True,timeout=20)
    if ok and p.returncode: fail('Команда read-only проверки не выполнена: '+args[0])
    return p

def jsonrun(*args):
    return json.loads(run(*args).stdout)

def table100():
    p=run('ip','-j','-4','route','show','table','100',ok=False)
    if p.returncode:
        if 'FIB table does not exist' in p.stderr:
            return []
        fail('Нельзя прочитать table100; ошибка не является отсутствием таблицы')
    return json.loads(p.stdout)

def osrelease():
    d={}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1);d[k]=v.strip('"')
    return d

def explicit_awg1_command(property_value, verb):
    """Не принимать подстроку awg1.conf.bak или shell wrapper за прямой путь."""
    if verb not in ('up','down'):return False
    commands=re.findall(r'argv\[\]=(.*?)\s*;',property_value)
    if len(commands)!=1:return False
    try:argv=shlex.split(commands[0])
    except ValueError:return False
    return (len(argv)==3 and argv[0].startswith('/') and Path(argv[0]).name=='awg-quick'
            and argv[1:]==[verb,'/etc/amnezia/awg1.conf'])

def host(c, action):
    role=c['NODE_ROLE'];prefix=role.upper();new=not(c['SCENARIO']=='A' and role=='entry')
    o=osrelease()
    if o.get('ID')!='ubuntu' or o.get('VERSION_ID')!='24.04':
        fail('Поддерживается только подтверждаемая Ubuntu 24.04 amd64')
    if o.get('PRETTY_NAME') != c[prefix+'_OS_DESCRIPTION']:
        fail('Точный релиз ОС не совпал с inventory')
    if run('dpkg','--print-architecture').stdout.strip()!='amd64':
        fail('Непроверенная архитектура; требуется amd64')
    if run('uname','-r').stdout.strip()!=c[prefix+'_KERNEL']:
        fail('Ядро не совпало с inventory')
    if run('hostname','-s').stdout.strip()!=c[prefix+'_HOSTNAME']:
        fail('Это другой hostname; не тот VPS')
    if not Path('/run/systemd/system').is_dir(): fail('Нужен работающий systemd')
    if action=='install-awg':
        if not new: fail('Установка/обновление пакетов на действующей ENTRY A запрещена')
        # До установки iptables может отсутствовать. Установщик повторит полный preflight.
        for unit in ('ufw','firewalld','nftables'):
            if run('systemctl','is-active',unit,ok=False).returncode==0:
                fail('Активен чужой firewall manager; сначала отдельный аудит')
        import shutil
        for mount,minimum in [('/',6*1024**3),('/tmp',4*1024**3)]:
            if shutil.disk_usage(mount).free<minimum: fail('Недостаточно свободного места для DKMS: '+mount)
        mem={m[1]:int(m[2])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if (m:=re.match(r'^(MemAvailable|SwapFree):\s+(\d+)',line))}
        if sum(mem.values())<1024**3: fail('DKMS требует минимум 1 GiB доступной RAM+swap')
        for secureboot in Path('/sys/firmware/efi/efivars').glob('SecureBoot-*'):
            if secureboot.read_bytes()[4:5]==b'\x01': fail('Secure Boot включён; автоматическая настройка неподписанного DKMS запрещена')
        return
    if 'nf_tables' not in run('iptables','--version').stdout or 'nf_tables' not in run('ip6tables','--version').stdout:
        fail('Выбран backend iptables-nft; legacy backend не поддержан без отдельного аудита')
    # Нельзя смешать iptables-nft с самостоятельным native nft ruleset.
    if run('systemctl','is-active','ufw','firewalld','nftables',ok=False).stdout.split().count('active'):
        fail('Активен конкурирующий firewall manager; автоматическая перенастройка запрещена')
    nft=run('nft','list','tables').stdout
    for line in nft.splitlines():
        if line.strip() not in ('table ip filter','table ip nat','table ip mangle','table ip raw','table ip security','table ip6 filter','table ip6 nat','table ip6 mangle','table ip6 raw','table ip6 security'):
            fail('Обнаружена неучтённая nft table; нужен отдельный аудит backend')
    # Не игнорировать legacy правила, скрытые параллельно nft backend.
    for binary in ('iptables-legacy-save','ip6tables-legacy-save'):
        p=run(binary,ok=False)
        if p.returncode==0 and re.search(r'^-A |^:[A-Z]+ (DROP|REJECT)',p.stdout,re.M):
            fail('Есть параллельные legacy firewall rules')
    wan=c[prefix+'_WAN_IF'];address=c[prefix+'_PUBLIC_IP']
    addrs=jsonrun('ip','-j','-4','address','show','dev',wan)
    if not any(a['local']==address for obj in addrs for a in obj.get('addr_info',[])):
        fail('Публичный IP должен реально находиться на WAN; 1:1 provider NAT требует отдельной реализации')
    routes=jsonrun('ip','-j','-4','route','show','default')
    if not routes or any(x.get('dev')!=wan for x in routes): fail('Конкурирующий default WAN; main не изменяется')
    # Два совпадающих default на исторической ENTRY допускаются, не очищаются.
    if len({x.get('gateway') for x in routes})!=1: fail('Несовпадающие default gateway')
    if new:
        for unit in ('ufw','firewalld','nftables','netfilter-persistent','awg-quick@awg0','awg-quick@awg1','wg-quick@wg0','wg-quick@wg1'):
            if run('systemctl','is-enabled',unit+'.service',ok=False).returncode==0:
                fail('Новый узел имеет конкурирующий enabled unit: '+unit)
        if len(routes)!=1: fail('Новый VPS должен иметь один однозначный default route')
        if any(x.get('ifname') not in ('lo',wan,'awg0','awg1') for x in jsonrun('ip','-j','link','show')):
            fail('Новый VPS содержит дополнительные interfaces; нужен аудит')
    client=ip.IPv4Network(c['CLIENT_CIDR']);transit=ip.IPv4Network(c['TRANSIT_CIDR'])
    for dev in jsonrun('ip','-j','-4','address','show'):
        for a in dev.get('addr_info',[]):
            net=ip.IPv4Network(a['local']+'/'+str(a['prefixlen']),strict=False)
            if (net.overlaps(client) and dev['ifname']!='awg0') or (net.overlaps(transit) and dev['ifname']!='awg1'):
                fail('Конфликт адресных сетей на другом интерфейсе')
    if role=='exit' and run('ip','link','show','awg0',ok=False).returncode==0:
        fail('EXIT не должен иметь awg0')
    allowed_rules={0,99,100,32766,32767} if role=='entry' else {0,32766,32767}
    for r in jsonrun('ip','-j','-4','rule','show'):
        if r['priority'] not in allowed_rules: fail('Неучтённое policy rule')
        if r['priority'] in (99,100):
            expected=c['CLIENT_CIDR'] if r['priority']==100 else c['ENTRY_AWG1_ADDR'].split('/')[0]
            if r.get('src','').removesuffix('/32')!=expected or str(r.get('table'))!='100':
                fail('Занят приоритет policy rule 99/100')
    rules=jsonrun('ip','-j','-4','rule','show')
    for pref,table in [(0,'local'),(32766,'main'),(32767,'default')]:
        base=[r for r in rules if r['priority']==pref]
        if len(base)!=1 or base[0].get('src')!='all' or str(base[0].get('table'))!=table:
            fail('Стандартное base policy rule изменено; его нельзя угадывать')
    if any(sum(r['priority']==n for r in rules)>1 for n in (99,100)):
        fail('Дублирующиеся приоритеты 99/100')
    if role=='entry':
        for r in table100():
            if r.get('dst')!='default' or not (r.get('dev')=='awg1' and r.get('metric',0)==0 or r.get('type')=='unreachable' and r.get('metric')==4278198272):
                fail('Неучтённый маршрут в policy table100')
    # Запрещён любой SNAT на ENTRY, в т.ч. слишком широкий -s 0/0.
    nat=run('iptables','-t','nat','-S').stdout
    if role=='entry' and re.search(r'-j (MASQUERADE|SNAT)',nat): fail('На ENTRY обнаружен NAT; двойной NAT запрещён')
    if role=='exit':
        for line in nat.splitlines():
            if re.search(r'-j (MASQUERADE|SNAT)',line) and not ('-s '+c['CLIENT_CIDR'] in line and '-o '+wan in line and '-j MASQUERADE' in line):
                fail('На новом EXIT есть чужой NAT')
    if new and not Path('/etc/paco-deploy/runtime.env').exists():
        # Не выдать чужой уже работающий VPN за пустой VPS.
        for intf in ('awg0','awg1','wg0','tun0'):
            if run('ip','link','show',intf,ok=False).returncode==0: fail('VPS не пустой: VPN interface уже существует')
        if list(Path('/etc/amnezia').glob('**/*.conf')): fail('VPS не пустой: есть AWG-конфиги')
    if action=='install-awg': return
    if new:
        for package,version in [('amneziawg-tools',TOOLS_PACKAGE),('amneziawg-dkms',DKMS_PACKAGE)]:
            if run('dpkg-query','-W','-f=${Version}',package).stdout!=version:
                fail('Версия пакета не совпала: '+package)
    else:
        if run('awg','--version').stdout.strip()!=c.get('ENTRY_AWG_TOOLS_VERSION'):
            fail('Не подтверждена точная текущая версия AWG на ENTRY')
        if c['LEGACY_POLICY_AUDITED']!='YES': fail('Нужен аудит legacy unit/hooks')
        for unit in ('paco-failclosed.service','netfilter-persistent.service'):
            if run('systemctl','is-enabled',unit,ok=False).returncode or run('systemctl','is-active',unit,ok=False).returncode:
                fail('Исходный persistent failclosed unit не enabled/active')
        for p in ('/etc/amnezia/awg0.conf','/etc/amnezia/awg1.conf'):
            secure_file(p,root=True)
        if run('systemctl','is-active','paco-awg-traffic.timer',ok=False).returncode:
            fail('Исходный paco-awg-traffic.timer не активен; отдельная диагностика')
        if 'ExecStop=' in run('systemctl','cat','paco-failclosed.service').stdout:
            fail('Legacy failclosed имеет ExecStop: проверить независимость правил')
        for prop,verb in [('ExecStart','up'),('ExecStop','down')]:
            unit=run('systemctl','show','awg-quick@awg1.service','-p',prop,'--value').stdout
            if not explicit_awg1_command(unit,verb):
                fail('AWG1 '+prop+' не является прямым awg-quick '+verb+' с подтверждённым путём; отдельный аудит, STOP')
        for name in ('awg0','awg1'):
            if run('systemctl','is-active','awg-quick@'+name+'.service',ok=False).returncode:
                fail('Исходный AWG unit не активен')
        current=parse_awg('/etc/amnezia/awg1.conf')
        p=subprocess.run(['awg','pubkey'],input=current[0][1]['PrivateKey']+'\n',capture_output=True,text=True,timeout=10)
        if p.returncode or p.stdout.strip()!=run('awg','show','awg1','public-key').stdout.strip():
            fail('AWG1 file private key не соответствует runtime public key')
        file_peers={p['PublicKey'] for n,p in parse_awg('/etc/amnezia/awg0.conf') if n=='Peer'}
        if file_peers!=set(run('awg','show','awg0','peers').stdout.split()):
            fail('Состав AWG0 peer в файле отличается от runtime')
        if any(k in parse_awg('/etc/amnezia/awg0.conf')[0][1] for k in ('PreUp','PostUp','PreDown','PostDown')):
            fail('У существующего AWG0 есть hooks: требуется отдельный аудит, автоматически не меняются')
        for pref in (99,100):
            if sum(r['priority']==pref for r in rules)!=1: fail('До cutover отсутствует legacy failclosed rule')
        if run('iptables','-C','FORWARD','-i','awg0','-s',c['CLIENT_CIDR'],'!','-o','awg1','-j','DROP',ok=False).returncode:
            fail('Не подтверждён исходный failclosed DROP для безопасного rollback')
        if not any(r.get('type')=='unreachable' and r.get('dst')=='default' and r.get('metric')==4278198272 for r in table100()):
            fail('Нет исходного unreachable для безопасного rollback')
    # Пакетная версия сама по себе недостаточна. Только kernel implementation, без silent userspace fallback.
    if run('modinfo','amneziawg',ok=False).returncode: fail('Нет модуля AWG для текущего ядра; NO-GO до DKMS проверки')
    profile(secure_file(c['TRANSIT_PROFILE_FILE'],root=True))
    if c.get('TRANSIT_PSK_FILE','NONE')!='NONE': secure_file(c['TRANSIT_PSK_FILE'],root=True)
    ports=run('ss','-H','-lntup').stdout
    listening=set()
    for line in ports.splitlines():
        cols=line.split()
        if len(cols)>4:
            try: listening.add((cols[0],int(cols[4].rsplit(':',1)[1])))
            except ValueError: pass
    if ('tcp',int(c['SSH_PORT'])) not in listening:
        fail('SSH_PORT не слушается; сохранение доступа не подтверждено')
    if os.environ.get('SSH_CONNECTION'):
        connection=os.environ['SSH_CONNECTION'].split()
        if len(connection)!=4 or ip.ip_address(connection[0]) not in ip.IPv4Network(c['SSH_SOURCE_CIDR']) or connection[3]!=c['SSH_PORT']:
            fail('Текущая SSH-сессия не совпала с IPv4 whitelist/портом; используйте проверенную консоль')
    for port,iface in [(int(c['TRANSIT_PORT']),'awg1')]+([(int(c['CLIENT_PORT']),'awg0')] if role=='entry' else []):
        if ('udp',port) in listening and run('awg','show',iface,'listen-port',ok=False).stdout.strip()!=str(port):
            fail('Порт AWG занят не подтверждённым AWG interface')
    # Не выводить строки ss; на новых серверах передавать только SSH/системные DNS/DHCP/NTP.
    if new:
        allowed={22,53,68,123,323,546,int(c['SSH_PORT']),int(c['TRANSIT_PORT'])}
        if role=='entry': allowed.add(int(c['CLIENT_PORT']))
        for line in ports.splitlines():
            cols=line.split()
            if len(cols)>4:
                try: port=int(cols[4].rsplit(':',1)[1])
                except ValueError: continue
                if port not in allowed: fail('Неучтённый слушающий порт на новом VPS')
    print('PASS: OS/kernel/host/WAN/backend/routes/toolchain read-only preflight')

def verify(c):
    role=c['NODE_ROLE'];wan=c[role.upper()+'_WAN_IF']
    new=not(c['SCENARIO']=='A' and role=='entry')
    for unit in ['paco-deploy-guard.service',('paco-awg1.service' if new else 'awg-quick@awg1.service')]+([('paco-awg0.service' if new else 'awg-quick@awg0.service')] if role=='entry' else []):
        if run('systemctl','is-active',unit,ok=False).returncode or run('systemctl','is-enabled',unit,ok=False).returncode:
            fail('Не enabled/active unit: '+unit)
    other=c['EXIT_PUBLIC_IP'] if role=='entry' else c['ENTRY_PUBLIC_IP']
    for args in [('-s',other+'/32','-p','udp','--dport',c['TRANSIT_PORT'],'-j','ACCEPT'),
                 ('!','-s',other+'/32','-p','udp','--dport',c['TRANSIT_PORT'],'-j','DROP')]:
        if run('iptables','-C','INPUT',*args,ok=False).returncode: fail('Не подтверждён transit IPv4 whitelist/drop')
    if run('ip6tables','-C','INPUT','-p','udp','--dport',c['TRANSIT_PORT'],'-j','DROP',ok=False).returncode:
        fail('Не заблокирован transit UDP по IPv6')
    if run('sysctl','-n','net.ipv4.ip_forward').stdout.strip()!='1': fail('IPv4 forwarding выключен')
    if role=='entry':
        from data import peer_fingerprint
        _,count=peer_fingerprint('/etc/amnezia/awg0.conf')
        file_peers={p['PublicKey'] for n,p in parse_awg('/etc/amnezia/awg0.conf') if n=='Peer'}
        if count==0 or file_peers!=set(run('awg','show','awg0','peers').stdout.split()): fail('AWG0 peer set не совпал с файлом/пуст')
        rules=jsonrun('ip','-j','-4','rule','show')
        for pref,src in [(100,c['CLIENT_CIDR']),(99,c['ENTRY_AWG1_ADDR'].split('/')[0])]:
            matches=[r for r in rules if r['priority']==pref and r.get('src','').removesuffix('/32')==src and str(r.get('table'))=='100']
            if len(matches)!=1: fail('Policy rule отсутствует/дублируется')
        routes=jsonrun('ip','-j','-4','route','show','table','100')
        if not any(r.get('type')=='unreachable' and r.get('dst')=='default' and r.get('metric')==4278198272 for r in routes):
            fail('Нет permanent unreachable fallback')
        route=jsonrun('ip','-j','-4','route','get','1.1.1.1','from',c['TEST_CLIENT_IP'],'iif','awg0')
        if len(route)!=1 or route[0].get('dev')!='awg1' or str(route[0].get('table'))!='100': fail('Клиентский маршрут не идёт в awg1/table100')
        # Первый non-policy FORWARD entry обязан быть независимым DROP.
        ruleset=run('iptables','-S','FORWARD').stdout.splitlines()
        first=next((x for x in ruleset if x.startswith('-A ')), '')
        if first!='-A FORWARD -i awg0 ! -o awg1 -j DROP': fail('Failclosed DROP не первый в FORWARD')
        for args in [('-i','awg0','-s',c['CLIENT_CIDR'],'!','-o','awg1','-j','DROP')]:
            if run('iptables','-C','FORWARD',*args,ok=False).returncode: fail('Нет независимого client DROP')
        if run('ip6tables','-C','FORWARD','-i','awg0','-j','DROP',ok=False).returncode: fail('Нет IPv6 FORWARD block')
        forward=[('-i','awg0','-o','awg1','-s',c['CLIENT_CIDR'],'-j','ACCEPT'),
                 ('-i','awg1','-o','awg0','-d',c['CLIENT_CIDR'],'-m','conntrack','--ctstate','RELATED,ESTABLISHED','-j','ACCEPT')]
    else:
        routes=jsonrun('ip','-j','-4','route','show',c['CLIENT_CIDR'])
        if len(routes)!=1 or routes[0].get('dev')!='awg1': fail('Нет обратного маршрута клиента')
        if run('iptables','-t','nat','-C','POSTROUTING','-s',c['CLIENT_CIDR'],'-o',wan,'-j','MASQUERADE',ok=False).returncode:
            fail('Нет точного SNAT client network')
        forward=[('-i','awg1','-o',wan,'-s',c['CLIENT_CIDR'],'-j','ACCEPT'),
                 ('-i',wan,'-o','awg1','-d',c['CLIENT_CIDR'],'-m','conntrack','--ctstate','RELATED,ESTABLISHED','-j','ACCEPT')]
    for args in forward:
        if run('iptables','-C','FORWARD',*args,ok=False).returncode: fail('Нет точного forward/stateful return rule')
    handshakes=run('awg','show','awg1','latest-handshakes').stdout.splitlines()
    if len(handshakes)!=1 or not 0 <= time.time()-int(handshakes[0].split()[1]) <= 180:
        fail('Нет свежего sole-peer handshake (<=180s)')
    peer_key=c['EXIT_TRANSIT_PUBLIC_KEY'] if role=='entry' else c['ENTRY_TRANSIT_PUBLIC_KEY']
    if handshakes[0].split()[0]!=peer_key: fail('Handshake получен от другого peer')
    # Ping считается функциональной transit проверкой, но не заменяет внешний клиентский тест.
    other=(c['EXIT_AWG1_ADDR'] if role=='entry' else c['ENTRY_AWG1_ADDR']).split('/')[0]
    if run('ping','-c','3','-W','2','-I','awg1',other,ok=False).returncode: fail('Transit ping не прошёл')
    print('PASS: route/policy/firewall/NAT/fresh handshake/transit ping')

def evidence(c, path):
    secure_file(path,root=True)
    d=json.loads(Path(path).read_text())
    for k in ('dns','https','native_ipv6_blocked','route_loss_failclosed','awg1_stop_failclosed','rollback_drill','ssh_new_session','offsite_backup','reboot_exit','reboot_entry'):
        if d.get(k) is not True: fail('Не пройдена операторская приёмка: '+k)
    if d.get('scenario')!=c['SCENARIO'] or d.get('observed_exit_ip')!=c['EXIT_PUBLIC_IP']:
        fail('Клиентский внешний IPv4/сценарий не совпал')
    if not isinstance(d.get('checked_at_epoch'),int) or not 0 <= time.time()-d['checked_at_epoch'] <= 1800:
        fail('Acceptance устарел: нужен свежий тест <=30min')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if d.get(c['NODE_ROLE']+'_boot_id')!=boot: fail('Acceptance относится к другому boot')
    if c['NODE_ROLE']=='entry':
        from data import peer_fingerprint
        h,n=peer_fingerprint('/etc/amnezia/awg0.conf')
        if d.get('awg0_peer_fingerprint')!=h or d.get('awg0_peer_count')!=n or n==0:
            fail('Acceptance не совпал с текущим AWG0 peer manifest')
    print('PASS: fresh operator acceptance evidence (attestation, не удалённое измерение)')

if __name__=='__main__':
    try:
        cmd,config,inventory,*args=sys.argv[1:]
        c=validate(envfiles([config,inventory]))
        if cmd=='preflight': host(c,args[0])
        elif cmd=='verify': verify(c)
        elif cmd=='evidence': evidence(c,args[0])
        else: fail('Неизвестная проверка')
    except Exception as e:
        from data import NoGo
        print('NO-GO: '+(str(e) if isinstance(e,NoGo) else type(e).__name__+' (значения скрыты)'),file=sys.stderr)
        sys.exit(2)
