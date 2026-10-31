#!/usr/bin/env python3
"""Только рендеринг файлов и standalone verify; никогда systemctl reload/start."""
import os
from pathlib import Path
import re
import string
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
from data import NoGo, atomic, fail

KIT = Path(__file__).resolve().parents[1]
RUNTIME = '/usr/local/lib/paco-deploy'

def template(name):
    return string.Template((KIT/'templates'/name).read_text()).substitute(RUNTIME=RUNTIME)

def guard(scenario, role):
    if scenario not in ('A','B') or role not in ('entry','exit'):
        fail('Неизвестные scenario/role для guard')
    name = 'paco-deploy-guard-A-entry.service.in' if (scenario,role)==('A','entry') else 'paco-deploy-guard-new-node.service.in'
    return template(name)

def stage_a(directory):
    d=Path(directory)
    d.mkdir(mode=0o700,parents=True,exist_ok=True)
    atomic(d/'paco-deploy-guard.service',guard('A','entry'))
    for intf in ('awg0','awg1'):
        atomic(d/f'awg-quick@{intf}.service.d/90-paco-guard.conf',template('awg-entry-A-guard.conf.in'))
    atomic(d/'awg-quick@awg1.service.d/91-paco-route.conf',template('awg-entry-A-route.conf.in'))

def cycle_diagnostics(result):
    text=(result.stderr or '').lower()
    return any(x in text for x in ('ordering cycle','dependency cycle','found cycle'))

def verify_live_a(directory):
    """Реальные host units + будущие drop-ins. Не заменяет их на fixtures.

    До установки runtime executable временно указывает на тот же исходник KIT.
    [Unit] и остальные зависимости остаются в точности как у staged файлов.
    После установки engine повторяет verify с окончательным путём.
    """
    d=Path(directory)
    if not (d/'paco-deploy-guard.service').is_file(): fail('Нет staged guard')
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+',str(KIT)):
        fail('Для live graph verification нужен путь KIT без пробелов/спецсимволов')
    with tempfile.TemporaryDirectory(prefix='live-graph-',dir=d) as tmp:
        overlay=Path(tmp)
        for p in d.rglob('*'):
            if p.is_file() and overlay not in p.parents:
                # Подстановка только executable на [Service] строках, не графа.
                text=p.read_text()
                lines=[]
                for line in text.splitlines():
                    if line.startswith(('ExecStart=','ExecStartPost=','ExecStopPost=')):
                        line=line.replace(RUNTIME,str(KIT))
                    lines.append(line)
                atomic(overlay/p.relative_to(d),'\n'.join(lines)+'\n')
        env=os.environ.copy()
        paths=[str(overlay),'/etc/systemd/system','/run/systemd/system','/run/systemd/generator.early',
               '/run/systemd/generator','/run/systemd/generator.late','/usr/local/lib/systemd/system',
               '/usr/lib/systemd/system','/lib/systemd/system']
        env['SYSTEMD_UNIT_PATH']=':'.join(paths)
        argv=['systemd-analyze','verify','--man=no','--generators=no',str(overlay/'paco-deploy-guard.service'),
              'awg-quick@awg0.service','awg-quick@awg1.service','paco-failclosed.service','netfilter-persistent.service']
        p=subprocess.run(argv,env=env,capture_output=True,text=True,timeout=45)
        # Не печатать stderr с host units: он может включать чужие приватные значения.
        if p.returncode or cycle_diagnostics(p):
            fail('Staged units несовместимы с графом этого хоста; NO-GO до локального аудита зависимостей')

def main():
    command,*args=sys.argv[1:]
    if command=='guard':
        print(guard(*args),end='')
    elif command=='stage-a':
        stage_a(args[0])
    elif command=='verify-live-a':
        verify_live_a(args[0])
        print('PASS: staged A ordering verified against host unit files (reboot/data plane ещё не проверены)')
    else:fail('Неизвестная операция unit helper')

if __name__=='__main__':
    try:main()
    except Exception as e:
        print('NO-GO: '+(str(e) if isinstance(e,NoGo) else type(e).__name__+'; значения скрыты'),file=sys.stderr)
        sys.exit(2)
