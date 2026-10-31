#!/usr/bin/env python3
"""Проверяет РЕАЛЬНЫЕ heredoc units в изолированном root, ничего не запускает.
Base targets/legacy services — fixtures; фактический dependency graph VPS не проверен.
"""
from pathlib import Path
import os
import re
import shutil
import string
import subprocess
import tempfile

kit=Path(__file__).resolve().parents[1]
variables=dict(RUNTIME='/usr/local/lib/paco-deploy',id='20261031T000000-00000000-0000-0000-0000-000000000000',
    TIMER='paco-rollback-20261031T000000-00000000-0000-0000-0000-000000000000',deadline='2026-11-01 00:00:00 UTC',
    legacy='paco-failclosed.service',u='awg-quick@awg0',intf='awg1')

def render(text):return string.Template(text).substitute(variables)

with tempfile.TemporaryDirectory() as temp:
    root=Path(temp);units=root/'etc/systemd/system';units.mkdir(parents=True)
    for name in ('basic','sysinit','shutdown','local-fs','network-pre','network-online','multi-user','timers','sockets','slices'):
        (units/(name+'.target')).write_text('[Unit]\nDescription=OFFLINE FIXTURE '+name+'\nDefaultDependencies=no\n')
    # Base executable/legacy stubs: только наличие/права, ни один из них не исполняется.
    for name in ('usr/bin/awg-quick','usr/bin/true','usr/local/lib/paco-deploy/common/runtime.sh','usr/local/lib/paco-deploy/common/rollback-runtime.sh'):
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o755)
    for name in ('netfilter-persistent','paco-failclosed','awg-quick@awg0','awg-quick@awg1'):
        (units/(name+'.service')).write_text('[Unit]\nDescription=OFFLINE FIXTURE\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
    written=[]
    for src in (kit/'common/lib.sh',kit/'common/engine.sh'):
        pattern=r'(?:write_new_file |write_file )("?/etc/systemd/system/[^\n]+?) <<EOF\n(.*?)\nEOF'
        for match in re.finditer(pattern,src.read_text(),re.S):
            target=render(match[1].strip('"'))
            contents=render(match[2])+'\n'
            p=root/target.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_text(contents)
            written.append(p)
            if 'paco-awg1.service' in target and target.endswith('.service'):
                q=p.with_name('paco-awg0.service');q.write_text(contents.replace('awg1','awg0'));written.append(q)
    assert len(written)>=7,'Не найдены все heredoc units'
    # unit verify получает целые service/timer, drop-ins подхватываются с диска.
    targets=[str(p) for p in units.glob('*.service')]+[str(p) for p in units.glob('*.timer')]
    p=subprocess.run(['systemd-analyze','verify','--man=no','--generators=no','--root='+str(root),*targets],capture_output=True,text=True)
    if p.stdout:print(p.stdout)
    if p.stderr:print(p.stderr)
    if p.returncode:raise SystemExit(p.returncode)
    print('PASS: systemd-analyze verify; rendered blocks:',len(written),'; base targets/legacy services are OFFLINE FIXTURES')
