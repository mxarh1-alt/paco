#!/usr/bin/env python3
"""Regression ordering models, standalone systemd-analyze: никакие units не стартуют.
Это расширенные fixtures, НЕ фактический граф Москвы/проверка boot.
"""
from pathlib import Path
import re
import string
import subprocess
import sys
import tempfile
sys.dont_write_bytecode=True
kit=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(kit/'common'))
from units import guard, stage_a, cycle_diagnostics

variables=dict(RUNTIME='/usr/local/lib/paco-deploy',id='20261031T000000-00000000-0000-0000-0000-000000000000',
    TIMER='paco-rollback-20261031T000000-00000000-0000-0000-0000-000000000000',deadline='2026-11-01 00:00:00 UTC',
    u='awg-quick@awg0',intf='awg1')

OLD_GUARD='''[Unit]
Description=NEGATIVE CONTROL v1 guard
DefaultDependencies=no
Wants=network-pre.target
After=local-fs.target netfilter-persistent.service paco-failclosed.service
Before=network-pre.target awg-quick@awg0.service awg-quick@awg1.service
[Service]
Type=oneshot
ExecStart=/usr/bin/true
'''

def fixture(root,scenario,role,old=False,bad_legacy=False):
    units=root/'etc/systemd/system';units.mkdir(parents=True)
    for name in ('basic','sysinit','shutdown','local-fs','network-pre','network','network-online','multi-user','timers','sockets','slices'):
        (units/(name+'.target')).write_text('[Unit]\nDescription=ORDERING MODEL '+name+'\nDefaultDependencies=no\n')
    (units/'network.target').write_text('[Unit]\nDescription=MODEL network\nDefaultDependencies=no\nWants=model-networkd.service\nAfter=model-networkd.service\n')
    (units/'network-online.target').write_text('[Unit]\nDescription=MODEL online\nDefaultDependencies=no\nRequires=model-wait-online.service\nAfter=network.target model-wait-online.service\n')
    services={
        'model-networkd':'Wants=network-pre.target\nAfter=network-pre.target local-fs.target\nBefore=network.target',
        'model-wait-online':'Requires=model-networkd.service\nAfter=model-networkd.service\nBefore=network-online.target',
        'netfilter-persistent':'After=local-fs.target\nBefore=network-pre.target',
        'paco-failclosed':'Wants=network-online.target\nAfter=network-online.target'+(' awg-quick@awg1.service' if bad_legacy else '')+'\nBefore=awg-quick@awg0.service',
        'awg-quick@awg0':'After=network-online.target',
        'awg-quick@awg1':'After=network-online.target',
    }
    for name,ordering in services.items():
        (units/(name+'.service')).write_text('[Unit]\nDescription=ORDERING MODEL\n'+ordering+'\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
    for name in ('usr/bin/awg-quick','usr/bin/true','usr/local/lib/paco-deploy/common/runtime.sh','usr/local/lib/paco-deploy/common/rollback-runtime.sh'):
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o755)
    # Реальные heredocs генератора AWG/timer, а не их неиспользуемые копии.
    blocks=0
    for src in (kit/'common/lib.sh',kit/'common/engine.sh'):
        pattern=r'(?:write_new_file |write_file )("?/etc/systemd/system/[^\n]+?) <<EOF\n(.*?)\nEOF'
        for m in re.finditer(pattern,src.read_text(),re.S):
            target=string.Template(m[1].strip('"')).substitute(variables)
            text=string.Template(m[2]).substitute(variables)+'\n'
            p=root/target.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);blocks+=1
            if target.endswith('paco-awg1.service') and role=='entry':
                p.with_name('paco-awg0.service').write_text(text.replace('awg1','awg0'));blocks+=1
    assert blocks>=4
    if (scenario,role)==('A','entry'):
        stage_a(units)
    else:
        (units/'paco-deploy-guard.service').write_text(guard(scenario,role))
    if old:(units/'paco-deploy-guard.service').write_text(OLD_GUARD)
    # Проверяем все jobs модели, включая network/legacy и prospective units.
    jobs=[str(p) for p in units.glob('*.service')]+[str(p) for p in units.glob('*.timer')]
    return subprocess.run(['systemd-analyze','verify','--man=no','--generators=no','--root='+str(root),*jobs],capture_output=True,text=True)

cases=[('v1-negative-cycle','A','entry',True,False,False),
       ('v2-A-entry-legacy-after-online','A','entry',False,False,True),
       ('v2-B-entry-early-guard','B','entry',False,False,True),
       ('v2-A-new-exit-early-guard','A','exit',False,False,True),
       ('v2-negative-legacy-after-awg1','A','entry',False,True,False)]
for name,scenario,role,old,bad,want_ok in cases:
    with tempfile.TemporaryDirectory() as temp:
        p=fixture(Path(temp),scenario,role,old,bad)
        ok=p.returncode==0 and not cycle_diagnostics(p)
        assert ok==want_ok,(name,p.returncode,p.stderr)
        if not want_ok:assert cycle_diagnostics(p),(name,'Ошибка вызвана не cycle',p.stderr)
        print('PASS:',name, '; '+('verify exit=0, no cycle' if want_ok else 'cycle correctly REJECTED (negative control)'))
print('5 ordering cases PASS (3 positive, 2 expected rejection); all are MODELS, no host graph/reboot was tested')
