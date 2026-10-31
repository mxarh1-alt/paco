#!/usr/bin/env python3
"""Локальные данные PACO. Не выполняет shell из inventory/config/AWG-конфигов."""
import base64
import hashlib
import ipaddress as ip
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path('/var/lib/paco-deploy')
FIELDS = set('SCENARIO NODE_ROLE ENTRY_HOSTNAME EXIT_HOSTNAME ENTRY_PUBLIC_IP EXIT_PUBLIC_IP ENTRY_WAN_IF EXIT_WAN_IF ENTRY_OS_DESCRIPTION EXIT_OS_DESCRIPTION ENTRY_KERNEL EXIT_KERNEL ENTRY_AWG_TOOLS_VERSION CLIENT_CIDR TRANSIT_CIDR ENTRY_AWG0_ADDR ENTRY_AWG1_ADDR EXIT_AWG1_ADDR CLIENT_PORT TRANSIT_PORT CLIENT_DNS MTU POLICY_TABLE CLIENT_RULE_PREF TRANSIT_RULE_PREF SSH_PORT SSH_SOURCE_CIDR ENTRY_TRANSIT_PUBLIC_KEY EXIT_TRANSIT_PUBLIC_KEY TRANSIT_PROFILE_FILE TRANSIT_PSK_FILE CLIENT_IDENTITY_STRATEGY RESTORE_AWG0_FILE RESTORE_MANAGER_DIR MANAGER_MODE CLIENT_IPV6_CAPTURE_VERIFIED LEGACY_POLICY_AUDITED PROVIDER_FIREWALL_VERIFIED ROLLBACK_SECONDS TEST_CLIENT_IP CLIENT_ENDPOINT OLD_EXIT_PUBLIC_IP OFFSITE_BACKUP_VERIFIED CLIENT_POLICY_EVIDENCE ACCEPTANCE_FILE'.split())
FIELDS.add('FIREWALL_BACKEND')
PROFILE = ('Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4')
CLIENT_PROFILE = dict(zip(PROFILE, ('5','10','50','12','12','12','12','1','2','3','4')))
TOOLS_PACKAGE = '1.0.20210914-0~202608130144+ee0f0a9~ubuntu24.04.1'
DKMS_PACKAGE = '1.0.0-0~202609061402+4569c4c~ubuntu24.04.1'

class NoGo(ValueError):
    pass

def fail(message):
    raise NoGo(message)

def secure_file(path, root=False):
    p = Path(path)
    st = p.lstat()
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o077:
        fail('Нужен обычный файл 0600 без symlink: '+str(p))
    if root and st.st_uid != 0:
        fail('Файл должен принадлежать root: '+str(p))
    return p

def atomic(path, data, mode=0o600):
    p = Path(path)
    if p.is_symlink():
        fail('Symlink запрещён: '+str(p))
    p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.'+p.name+'.', dir=p.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data if isinstance(data, bytes) else data.encode())
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, p)
        d = os.open(p.parent, os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def envfiles(paths):
    result = {}
    for path in paths:
        seen = set()
        for n, line in enumerate(Path(path).read_text().splitlines(), 1):
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            m = re.fullmatch(r'([A-Z][A-Z0-9_]*)=(.*)', line)
            if not m or m[1] not in FIELDS or m[1] in seen:
                fail(f'Недопустимое/повторное поле {path}:{n}')
            key = m[1]
            parts = shlex.split(m[2], comments=True)
            if len(parts) != 1 or any(c in parts[0] for c in '\n\r\x00`$\\'):
                fail(f'Нужно одно литеральное значение {path}:{n}')
            seen.add(key)
            result[key] = parts[0]
    return result

def required(c, key):
    v = c.get(key, '')
    if not v or 'TO_' in v:
        fail('Не заполнено поле '+key)
    return v

def pubkey(v):
    try:
        if len(base64.b64decode(v, validate=True)) != 32:
            fail('Неверный public key')
    except Exception:
        fail('Неверный public key (значение скрыто)')
    return v

def validate(c):
    for k in FIELDS - {'TRANSIT_PSK_FILE','OLD_EXIT_PUBLIC_IP','ENTRY_TRANSIT_PUBLIC_KEY','EXIT_TRANSIT_PUBLIC_KEY','ENTRY_AWG_TOOLS_VERSION','RESTORE_AWG0_FILE','RESTORE_MANAGER_DIR','ACCEPTANCE_FILE'}:
        required(c, k)
    if c['SCENARIO'] not in ('A','B') or c['NODE_ROLE'] not in ('entry','exit'):
        fail('Неверные SCENARIO/NODE_ROLE')
    if c['FIREWALL_BACKEND']!='iptables-nft':
        fail('Этот комплект использует только явно выбранный iptables-nft backend')
    for k in ('ENTRY_PUBLIC_IP','EXIT_PUBLIC_IP','CLIENT_DNS','TEST_CLIENT_IP'):
        a = ip.IPv4Address(c[k])
        if k.endswith('PUBLIC_IP') and not a.is_global:
            fail('Нужен реальный глобальный IPv4: '+k)
    if c['ENTRY_PUBLIC_IP'] == c['EXIT_PUBLIC_IP']:
        fail('ENTRY и EXIT должны различаться')
    client = ip.IPv4Network(c['CLIENT_CIDR'])
    transit = ip.IPv4Network(c['TRANSIT_CIDR'])
    if not client.is_private or not transit.is_private or client.overlaps(transit):
        fail('Подсети должны быть частными и не пересекаться')
    if transit.prefixlen != 30 or client.prefixlen != 24:
        fail('Этот проверяемый вариант поддерживает /24 клиентов и /30 транзита')
    for k, net in [('ENTRY_AWG0_ADDR',client),('ENTRY_AWG1_ADDR',transit),('EXIT_AWG1_ADDR',transit)]:
        a = ip.IPv4Interface(c[k])
        if a.network != net or a.ip not in list(net.hosts()):
            fail('Неверный адрес интерфейса '+k)
    if c['ENTRY_AWG1_ADDR'] == c['EXIT_AWG1_ADDR']:
        fail('Одинаковые transit addresses')
    if ip.IPv4Address(c['TEST_CLIENT_IP']) not in client or c['TEST_CLIENT_IP'] == str(ip.IPv4Interface(c['ENTRY_AWG0_ADDR']).ip):
        fail('Неверный TEST_CLIENT_IP')
    for k in ('ENTRY_WAN_IF','EXIT_WAN_IF'):
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',c[k]) or c[k].startswith(('awg','lo')):
            fail('Неверное имя WAN '+k)
    for k in ('ENTRY_HOSTNAME','EXIT_HOSTNAME','ENTRY_KERNEL','EXIT_KERNEL'):
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+', c[k]):
            fail('Неверное поле '+k)
    for k in ('CLIENT_PORT','TRANSIT_PORT','SSH_PORT'):
        if not c[k].isdigit() or not 1 <= int(c[k]) <= 65535:
            fail('Неверный порт '+k)
    if c['CLIENT_PORT'] == c['TRANSIT_PORT']:
        fail('Порты клиента и транзита совпали')
    ip.IPv4Network(c['SSH_SOURCE_CIDR'])
    if c['SSH_SOURCE_CIDR'] == '0.0.0.0/0':
        fail('SSH_SOURCE_CIDR должен быть точечным whitelist')
    for k, value in [('POLICY_TABLE','100'),('CLIENT_RULE_PREF','100'),('TRANSIT_RULE_PREF','99'),('MTU','1380')]:
        if c[k] != value:
            fail('Данный комплект фиксирует '+k+'='+value)
    if not c['ROLLBACK_SECONDS'].isdigit() or not 300 <= int(c['ROLLBACK_SECONDS']) <= 3600:
        fail('ROLLBACK_SECONDS должен быть 300..3600')
    if c['CLIENT_IDENTITY_STRATEGY'] not in ('RESTORE_FROM_OWNER_BACKUP','REISSUE_ALL','UNCHANGED'):
        fail('Неверный CLIENT_IDENTITY_STRATEGY')
    if c['MANAGER_MODE'] not in ('UNCHANGED','NONE','RESTORE_OFFLINE'):
        fail('Менеджер: поддерживаются UNCHANGED/NONE/RESTORE_OFFLINE')
    if c['SCENARIO'] == 'A':
        if c['CLIENT_IDENTITY_STRATEGY'] != 'UNCHANGED' or c['MANAGER_MODE'] != 'UNCHANGED':
            fail('В A клиенты и менеджер остаются без изменений')
        ip.IPv4Address(required(c,'OLD_EXIT_PUBLIC_IP'))
    elif c['CLIENT_IDENTITY_STRATEGY'] == 'UNCHANGED' or c['MANAGER_MODE'] == 'UNCHANGED':
        fail('В B надо явно выбрать миграцию/новые идентичности и менеджер')
    if c['SCENARIO'] == 'B' and c['ENTRY_OS_DESCRIPTION'] != c['EXIT_OS_DESCRIPTION']:
        fail('В B нужен один точный релиз Ubuntu')
    if c['CLIENT_ENDPOINT'] != c['ENTRY_PUBLIC_IP']+':'+c['CLIENT_PORT']:
        fail('В этом варианте CLIENT_ENDPOINT должен совпадать с новым ENTRY IPv4:port')
    for k in ('TRANSIT_PROFILE_FILE','CLIENT_POLICY_EVIDENCE'):
        if not c[k].startswith('/') or not re.fullmatch(r'/[a-zA-Z0-9/_.-]+',c[k]):
            fail('Нужен абсолютный безопасный путь '+k)
    for k in ('ENTRY_TRANSIT_PUBLIC_KEY','EXIT_TRANSIT_PUBLIC_KEY'):
        if c.get(k) and 'TO_' not in c[k]:
            pubkey(c[k])
    return c

def profile(path):
    d = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        m = re.fullmatch(r'\s*(Jc|Jmin|Jmax|S[1-4]|H[1-4])\s*=\s*([0-9]+)\s*',line)
        if not m or m[1] in d:
            fail('Transit profile: допустимы только уникальные Jc/Jmin/Jmax/S1-S4/H1-H4 integers')
        d[m[1]] = m[2]
    if set(d) != set(PROFILE):
        fail('Transit profile должен содержать весь набор Jc/Jmin/Jmax/S1-S4/H1-H4')
    if not 1 <= int(d['Jc']) <= 128 or not 0 <= int(d['Jmin']) < int(d['Jmax']) <= 1280:
        fail('Неверные J-параметры')
    if any(not 0 <= int(d[k]) <= 1024 for k in ('S1','S2','S3','S4')) or int(d['S1'])+56 == int(d['S2']):
        fail('Неверные S-параметры')
    hs = [int(d[k]) for k in ('H1','H2','H3','H4')]
    if len(set(hs)) != 4 or any(not 0 <= h < 2**32 for h in hs):
        fail('Неверные H-параметры')
    return d

def parse_awg(path):
    sections = []
    for line in Path(path).read_text().splitlines():
        line = line.split('#',1)[0].strip()
        if not line:
            continue
        if line in ('[Interface]','[Peer]'):
            sections.append((line[1:-1],{}))
        elif '=' in line and sections:
            k,v = (x.strip() for x in line.split('=',1))
            if k in sections[-1][1]:
                fail('Повторное поле в AWG-конфиге (значение скрыто)')
            sections[-1][1][k] = v
        else:
            fail('Неверный синтаксис AWG-конфига (строка скрыта)')
    if not sections or sections[0][0] != 'Interface' or sum(n=='Interface' for n,_ in sections) != 1:
        fail('Ожидается один [Interface]')
    return sections

def stripped(sections):
    quick = {'Address','MTU','DNS','Table','PreUp','PostUp','PreDown','PostDown','SaveConfig'}
    return ''.join('['+n+']\n'+''.join(f'{k} = {v}\n' for k,v in d.items() if k not in quick)+'\n' for n,d in sections)

def peer_fingerprint(path):
    peers = []
    for n,d in parse_awg(path):
        if n == 'Peer':
            pubkey(d.get('PublicKey',''))
            peers.append((d['PublicKey'], d.get('AllowedIPs',''), d.get('PresharedKey','')))
    return hashlib.sha256(json.dumps(sorted(peers)).encode()).hexdigest(),len(peers)

def render_transit(c, private, existing=None):
    role = c['NODE_ROLE']
    d = profile(c['TRANSIT_PROFILE_FILE'])
    d = {'PrivateKey':private,**d,'Address':c['ENTRY_AWG1_ADDR'] if role=='entry' else c['EXIT_AWG1_ADDR'],
         'ListenPort':c['TRANSIT_PORT'],'MTU':c['MTU'],'Table':'off'}
    other = 'EXIT' if role == 'entry' else 'ENTRY'
    p = {'PublicKey':pubkey(required(c,other+'_TRANSIT_PUBLIC_KEY')),
         'AllowedIPs':'0.0.0.0/0' if role=='entry' else str(ip.IPv4Interface(c['ENTRY_AWG1_ADDR']).ip)+'/32, '+c['CLIENT_CIDR'],
         'Endpoint':c[other+'_PUBLIC_IP']+':'+c['TRANSIT_PORT'],'PersistentKeepalive':'25'}
    if c.get('TRANSIT_PSK_FILE','NONE') != 'NONE':
        value=secure_file(c['TRANSIT_PSK_FILE'],root=True).read_text().strip()
        pubkey(value)
        p['PresharedKey']=value
    if existing:
        old = parse_awg(existing)
        if len(old) != 2 or old[1][0] != 'Peer':
            fail('A требует ровно один старый transit peer')
        oi = old[0][1]
        if oi.get('Address')!=c['ENTRY_AWG1_ADDR'] or oi.get('ListenPort')!=c['TRANSIT_PORT']:
            fail('Адрес/порт действующего AWG1 не совпали с inventory')
        allowed = set(PROFILE) | {'PrivateKey','Address','ListenPort','MTU','Table','PreUp','PostUp','PreDown','PostDown','SaveConfig'}
        if set(oi)-allowed:
            fail('Неизвестные AWG1 параметры; нужна отдельная проверка совместимости')
        if any(oi.get(k)!=v for k,v in profile(c['TRANSIT_PROFILE_FILE']).items()):
            fail('Transit profile не совпал с действующим AWG1')
        if old[1][1].get('PresharedKey') and 'PresharedKey' not in p:
            fail('Старый AWG1 использует PSK: нужен локальный TRANSIT_PSK_FILE, NONE запрещён')
        # PrivateKey берётся исключительно из действующего локального AWG1.
        d['PrivateKey'] = oi['PrivateKey']
    return [('Interface',d),('Peer',p)]

def render(sections):
    return ''.join('['+n+']\n'+''.join(f'{k} = {v}\n' for k,v in d.items())+'\n' for n,d in sections)

def restore_clients(c, source):
    s = parse_awg(source)
    d = s[0][1]
    if any(d.get(k)!=v for k,v in CLIENT_PROFILE.items()):
        fail('AWG0 backup не совпал с подтверждённым клиентским PACO-профилем')
    allowed=set(PROFILE)|{'PrivateKey','Address','ListenPort','MTU','Table','SaveConfig'}
    if set(d)-allowed:
        fail('AWG0 backup содержит hooks/неподдерживаемые поля; отдельный ручной аудит')
    if d.get('Address') != c['ENTRY_AWG0_ADDR'] or d.get('ListenPort') != c['CLIENT_PORT']:
        fail('AWG0 адрес/порт backup не совпал с inventory')
    pubkey(d.get('PrivateKey',''))
    used = set()
    for n,p in s[1:]:
        if n != 'Peer' or set(p)-{'PublicKey','PresharedKey','AllowedIPs'}:
            fail('Импорт peer: разрешены только PublicKey/PresharedKey/AllowedIPs')
        pubkey(p.get('PublicKey',''))
        if 'PresharedKey' in p:
            pubkey(p['PresharedKey'])
        a = ip.IPv4Interface(p.get('AllowedIPs',''))
        if a.network.prefixlen != 32 or a.ip not in ip.IPv4Network(c['CLIENT_CIDR']) or a.ip == ip.IPv4Interface(c['ENTRY_AWG0_ADDR']).ip or str(a.ip) in used:
            fail('Конфликт/недопустимый AllowedIPs клиента')
        used.add(str(a.ip))
    if not used:
        fail('Backup не содержит peer')
    d['MTU']=c['MTU']; d['Table']='off'; d.pop('SaveConfig',None)
    return s

def sqlite_copy(src, dst):
    secure_file(src,root=os.geteuid()==0)
    a=sqlite3.connect(Path(src).as_uri()+'?mode=ro',uri=True)
    fd,name=tempfile.mkstemp(dir=Path(dst).parent)
    os.close(fd)
    try:
        b=sqlite3.connect(name)
        a.backup(b)
        if b.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            fail('SQLite integrity_check failed')
        b.close(); a.close()
        os.chmod(name,0o600); os.replace(name,dst)
    finally:
        if os.path.exists(name): os.unlink(name)

def main():
    cmd,*args=sys.argv[1:]
    if cmd=='env':
        c=envfiles(args)
        validate(c)
        for k,v in sorted(c.items()): print(k+'='+v)
    elif cmd=='fingerprint':
        h,n=peer_fingerprint(args[0]);print(h,n)
    elif cmd=='compare-identity':
        a,b=(parse_awg(p) for p in args)
        if a[0][1].get('PrivateKey')!=b[0][1].get('PrivateKey') or peer_fingerprint(args[0])!=peer_fingerprint(args[1]):
            fail('Импорт заменил бы серверную/клиентские идентичности')
    elif cmd=='export-profile':
        d=parse_awg(args[0])[0][1]
        if any(k not in set(PROFILE)|{'PrivateKey','Address','ListenPort','MTU','Table','PreUp','PostUp','PreDown','PostDown','SaveConfig'} for k in d):
            fail('Неизвестные параметры: автоматический экспорт профиля запрещён')
        for k in PROFILE:
            if k not in d: fail('Нет '+k+'; нельзя предполагать значение по умолчанию')
            print(k+' = '+d[k])
    elif cmd=='transit':
        c=validate(envfiles(args[:2]))
        key=secure_file(args[2],root=True).read_text().strip()
        pubkey(key)
        sections=render_transit(c,key,args[4] if len(args)>4 else None)
        atomic(args[3],render(sections))
    elif cmd=='strip':
        atomic(args[1],stripped(parse_awg(args[0])))
    elif cmd=='atomic-copy':
        atomic(args[1],Path(args[0]).read_bytes())
    elif cmd=='manager-report':
        import ast
        c=validate(envfiles(args[:2]));text=Path(args[2]).read_text();tree=ast.parse(text)
        fields={}
        for node in tree.body:
            if isinstance(node,ast.Assign):
                for target in node.targets:
                    if isinstance(target,ast.Name) and target.id in ('ENDPOINT','INTERFACE','NET'):
                        try: fields[target.id]=ast.literal_eval(node.value)
                        except (ValueError,TypeError): pass
        report={'offline_only':True,'source_not_executed':True,'version_0_2_4_marker_present':bool(re.search(r'\b0\.2\.4\b',text)),
            'endpoint_matches_new_entry':fields.get('ENDPOINT')==c['CLIENT_ENDPOINT'],
            'interface_matches_awg0':fields.get('INTERFACE')=='awg0','net_matches':fields.get('NET')==c['CLIENT_CIDR'],
            'activation_status':'NO-GO: нужен локальный аудит кода и units; marker/AST не являются экспертизой'}
        atomic(args[3],json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    elif cmd=='restore-clients':
        c=validate(envfiles(args[:2]));secure_file(args[2],root=True)
        atomic(args[3],render(restore_clients(c,args[2])))
    elif cmd=='sqlite-copy':
        sqlite_copy(*args)
    elif cmd=='record':
        tx=Path(args[0]);record=json.loads(args[1])
        with (tx/'undo.jsonl').open('a') as f:
            os.fchmod(f.fileno(),0o600); f.write(json.dumps(record)+'\n');f.flush();os.fsync(f.fileno())
    elif cmd=='record-command':
        tx=Path(args[0])
        with (tx/'undo.jsonl').open('a') as f:
            os.fchmod(f.fileno(),0o600);f.write(json.dumps({'command':args[1:]})+'\n');f.flush();os.fsync(f.fileno())
    elif cmd=='put':
        tx,src,dst=map(Path,args)
        if dst.is_symlink(): fail('Symlink target запрещён')
        token=hashlib.sha256(str(dst).encode()).hexdigest()
        old=tx/'files'/token
        old.parent.mkdir(mode=0o700,exist_ok=True)
        existed=dst.exists()
        if existed: atomic(old,dst.read_bytes(),stat.S_IMODE(dst.stat().st_mode))
        record={'file':str(dst),'old':str(old),'existed':existed,'mode':stat.S_IMODE(dst.stat().st_mode) if existed else 0o600}
        with (tx/'undo.jsonl').open('a') as f:
            f.write(json.dumps(record)+'\n');f.flush();os.fsync(f.fileno())
        atomic(dst,src.read_bytes(),stat.S_IMODE(src.stat().st_mode))
    elif cmd=='new-awg0':
        c=validate(envfiles(args[:2]));key=secure_file(args[2],root=True).read_text().strip();pubkey(key)
        d={'PrivateKey':key,**CLIENT_PROFILE,'Address':c['ENTRY_AWG0_ADDR'],'ListenPort':c['CLIENT_PORT'],'MTU':c['MTU'],'Table':'off'}
        atomic(args[3],render([('Interface',d)]))
    elif cmd=='enroll':
        c=validate(envfiles(args[:2]));server=Path(args[2]);name=args[3];clientdir=Path(args[4])
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}',name): fail('Неверное имя клиента')
        clientdir.mkdir(mode=0o700,parents=True,exist_ok=True)
        sections=parse_awg(server)
        # Локальный приватный профиль не печатается и не включается в deploy ZIP.
        conf=clientdir/(name+'.conf')
        if conf.exists():
            cs=parse_awg(secure_file(conf,root=True));private=cs[0][1]['PrivateKey']
            address=cs[0][1]['Address']
        else:
            private=subprocess.check_output(['awg','genkey'],text=True).strip()
            used={ip.IPv4Interface(d['AllowedIPs']).ip for n,d in sections[1:]}
            used.add(ip.IPv4Interface(c['ENTRY_AWG0_ADDR']).ip)
            address=next((str(a)+'/32' for a in ip.IPv4Network(c['CLIENT_CIDR']).hosts() if a not in used),None)
            if address is None: fail('Нет свободного клиентского IPv4')
        public=subprocess.check_output(['awg','pubkey'],input=private+'\n',text=True,stderr=subprocess.DEVNULL).strip()
        serverpub=subprocess.check_output(['awg','pubkey'],input=sections[0][1]['PrivateKey']+'\n',text=True,stderr=subprocess.DEVNULL).strip()
        existing=[p for n,p in sections[1:] if p.get('PublicKey')==public]
        if existing and (len(existing)!=1 or existing[0].get('AllowedIPs')!=address): fail('Peer конфликтует с manifest клиента')
        if not existing: sections.append(('Peer',{'PublicKey':public,'AllowedIPs':address}))
        cd={'PrivateKey':private,**CLIENT_PROFILE,'Address':address,'DNS':c['CLIENT_DNS'],'MTU':c['MTU']}
        cp={'PublicKey':serverpub,'AllowedIPs':'0.0.0.0/0, ::/0','Endpoint':c['CLIENT_ENDPOINT'],'PersistentKeepalive':'25'}
        atomic(conf,render([('Interface',cd),('Peer',cp)]))
        atomic(server,render(sections))
    elif cmd=='probe-config':
        sections=parse_awg(args[0]);sections[0][1]['ListenPort']='0'
        atomic(args[1],stripped(sections))
    elif cmd=='probe-result':
        wanted=parse_awg(args[0])[0][1];actual=parse_awg(args[1])[0][1]
        for k in PROFILE:
            if wanted.get(k)!=actual.get(k): fail('Ядро не подтвердило round-trip параметра '+k)
    elif cmd=='undo':
        tx=Path(args[0]); errors=0
        progress=tx/'undo-completed.json'
        done=set(json.loads(progress.read_text())) if progress.exists() else set()
        lines=(tx/'undo.jsonl').read_text().splitlines()
        for index in reversed(range(len(lines))):
            if index in done: continue
            line=lines[index]
            r=json.loads(line)
            try:
                if 'command' in r:
                    command=r['command']
                    p=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
                    satisfied=p.returncode==0
                    if not satisfied and command[0] in ('iptables','ip6tables') and '-D' in command:
                        check=command.copy();pos=check.index('-D');check[pos]='-C'
                        a=subprocess.run(check,capture_output=True,timeout=10)
                        b=subprocess.run(command[:pos]+['-S',command[pos+1]],capture_output=True,timeout=10)
                        satisfied=a.returncode==1 and b.returncode==0
                    if not satisfied and command[:4]==['ip','-4','rule','del']:
                        p=subprocess.run(['ip','-j','-4','rule','show'],capture_output=True,text=True,timeout=10)
                        if p.returncode==0:
                            pref=int(command[command.index('pref')+1]);src=command[command.index('from')+1].removesuffix('/32')
                            satisfied=not any(x.get('priority')==pref and x.get('src','').removesuffix('/32')==src for x in json.loads(p.stdout))
                    if not satisfied:
                        errors+=1
                        continue
                else:
                    dst=Path(r['file'])
                    if r['existed']: atomic(dst,Path(r['old']).read_bytes(),r['mode'])
                    elif dst.exists(): dst.unlink()
                done.add(index)
                atomic(progress,json.dumps(sorted(done))+'\n')
            except Exception: errors+=1
        p=subprocess.run(['systemctl','daemon-reload'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        if p.returncode: errors+=1
        if errors: fail('Rollback не завершён полностью; нужна консоль. Ошибок: '+str(errors))
    else:
        fail('Неизвестная операция данных')

if __name__=='__main__':
    try: main()
    except Exception as e:
        # Никогда не печатать str(e): parser/OS могут включить секретную строку.
        message=str(e) if isinstance(e,NoGo) else type(e).__name__+'; проверьте локальные пути/права (значения скрыты)'
        print('NO-GO: '+message,file=sys.stderr)
        sys.exit(2)
