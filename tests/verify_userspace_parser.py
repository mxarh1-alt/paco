#!/usr/bin/env python3
"""Опциональная проверка доверенного AWG tools binary; kernel interface не создаётся."""
import base64
import os
from pathlib import Path
import subprocess
import tempfile

binary=os.environ.get('PACO_TEST_AWG_BIN')
if not binary:raise SystemExit('Укажите PACO_TEST_AWG_BIN на проверенный локальный awg binary')
root=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    p=Path(temp)/'parser.conf'
    key=base64.b64encode(bytes(range(32))).decode()  # только временные тестовые данные
    p.write_text('[Interface]\nPrivateKey = '+key+'\n'+(root/'config/transit-profile-B.conf.example').read_text());p.chmod(0o600)
    a=subprocess.run([binary,'setconf','paco-no-such',str(p)],capture_output=True,text=True)
    assert a.returncode!=0 and 'Configuration parsing error' not in a.stderr
    assert any(s in a.stderr for s in ('Unable to modify interface','Unable to access interface','No such device')),'Не доказано достижение netlink стадии'
    p.write_text(p.read_text()+'UnsupportedPACOFIELD = 1\n')
    b=subprocess.run([binary,'setconf','paco-no-such',str(p)],capture_output=True,text=True)
    assert b.returncode!=0 and 'Configuration parsing error' in b.stderr
    print('PASS: actual userspace parser accepts J/S1-S4/H1-H4 and rejects unknown field; kernel/VPN NOT tested')
