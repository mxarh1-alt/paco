#!/usr/bin/env python3
"""Изолированные тесты: temp files и mock commands, без root/SSH/сетевых изменений."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'common'))
import data
import checks

def fixture():
    # Адреса — только входные данные offline-тестов; сеть к ним не используется.
    return dict(SCENARIO='B',NODE_ROLE='entry',ENTRY_HOSTNAME='fixture-entry',EXIT_HOSTNAME='fixture-exit',
        ENTRY_PUBLIC_IP='1.1.1.1',EXIT_PUBLIC_IP='8.8.8.8',ENTRY_WAN_IF='ens3',EXIT_WAN_IF='ens3',
        ENTRY_OS_DESCRIPTION='Ubuntu 24.04.5 LTS',EXIT_OS_DESCRIPTION='Ubuntu 24.04.5 LTS',ENTRY_KERNEL='6.8.0-fixture',EXIT_KERNEL='6.8.0-fixture',
        CLIENT_CIDR='10.77.77.0/24',TRANSIT_CIDR='10.88.88.0/30',ENTRY_AWG0_ADDR='10.77.77.1/24',ENTRY_AWG1_ADDR='10.88.88.1/30',EXIT_AWG1_ADDR='10.88.88.2/30',
        CLIENT_PORT='60333',TRANSIT_PORT='60334',CLIENT_DNS='1.1.1.1',MTU='1380',FIREWALL_BACKEND='iptables-nft',POLICY_TABLE='100',CLIENT_RULE_PREF='100',TRANSIT_RULE_PREF='99',
        SSH_PORT='22',SSH_SOURCE_CIDR='192.0.2.10/32',ROLLBACK_SECONDS='1800',TEST_CLIENT_IP='10.77.77.2',
        TRANSIT_PROFILE_FILE='/root/paco/transit-profile.conf',TRANSIT_PSK_FILE='NONE',CLIENT_POLICY_EVIDENCE='/root/paco/policy.json',
        CLIENT_IPV6_CAPTURE_VERIFIED='NO',PROVIDER_FIREWALL_VERIFIED='NO',OFFSITE_BACKUP_VERIFIED='NO',LEGACY_POLICY_AUDITED='NO',
        CLIENT_IDENTITY_STRATEGY='REISSUE_ALL',CLIENT_ENDPOINT='1.1.1.1:60333',MANAGER_MODE='NONE')

def dummy_key(byte=1):
    import base64
    # Неприменимые тестовые данные, нигде не выводятся/не публикуются как credentials.
    return base64.b64encode(bytes([byte])*32).decode()

class Offline(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.p=Path(self.tmp.name);self.c=fixture()
    def tearDown(self): self.tmp.cleanup()
    def file(self,name,text):
        p=self.p/name;p.write_text(text);p.chmod(0o600);return p
    def server(self,extra=None):
        d={'PrivateKey':dummy_key(),**data.CLIENT_PROFILE,'Address':self.c['ENTRY_AWG0_ADDR'],'ListenPort':'60333','MTU':'1380','Table':'off'}
        d.update(extra or {})
        return [('Interface',d),('Peer',{'PublicKey':dummy_key(2),'AllowedIPs':'10.77.77.2/32'})]
    def test_valid_inventory(self): data.validate(self.c)
    def test_unfilled_inventory_blocks(self):
        self.c['EXIT_PUBLIC_IP']='TO_FILL'
        with self.assertRaises(data.NoGo): data.validate(self.c)
    def test_subnet_conflict_blocks(self):
        self.c['TRANSIT_CIDR']=self.c['CLIENT_CIDR']
        with self.assertRaises(data.NoGo):data.validate(self.c)
    def test_wan_injection_blocks(self):
        self.c['ENTRY_WAN_IF']='eth0;id'
        with self.assertRaises(data.NoGo):data.validate(self.c)
    def test_ssh_worldwide_blocks(self):
        self.c['SSH_SOURCE_CIDR']='0.0.0.0/0'
        with self.assertRaises(data.NoGo):data.validate(self.c)
    def test_shell_substitution_never_executes(self):
        marker=self.p/'executed'
        p=self.file('bad.env',"ENTRY_HOSTNAME='$(touch "+str(marker)+")'\n")
        with self.assertRaises(data.NoGo):data.envfiles([p])
        self.assertFalse(marker.exists())
    def test_secret_field_rejected(self):
        with self.assertRaises(data.NoGo):data.envfiles([self.file('bad.env','PRIVATE_KEY=forbidden\n')])
    def test_duplicate_field_rejected(self):
        with self.assertRaises(data.NoGo):data.envfiles([self.file('bad.env','SCENARIO=A\nSCENARIO=B\n')])
    def test_inventory_override_intentional(self):
        a=self.file('a.env','NODE_ROLE=entry\n');b=self.file('b.env','NODE_ROLE=exit\n')
        self.assertEqual(data.envfiles([a,b])['NODE_ROLE'],'exit')
    def test_b_identical_os_required(self):
        self.c['EXIT_OS_DESCRIPTION']='Ubuntu other'
        with self.assertRaises(data.NoGo):data.validate(self.c)
    def test_a_identity_change_blocks(self):
        self.c.update(SCENARIO='A',OLD_EXIT_PUBLIC_IP='9.9.9.9')
        with self.assertRaises(data.NoGo):data.validate(self.c)
    def test_endpoint_mismatch_blocks(self):
        self.c['CLIENT_ENDPOINT']='9.9.9.9:60333'
        with self.assertRaises(data.NoGo):data.validate(self.c)
    def test_missing_profile_parameter_blocks(self):
        p=self.file('profile','Jc = 5\n')
        with self.assertRaises(data.NoGo):data.profile(p)
    def test_profile_unsupported_field_blocks(self):
        p=self.file('profile',(ROOT/'config/transit-profile-B.conf.example').read_text()+'I1 = unknown\n')
        with self.assertRaises(data.NoGo):data.profile(p)
    def test_duplicate_headers_block(self):
        p=self.file('profile',(ROOT/'config/transit-profile-B.conf.example').read_text().replace('H4 = 4','H4 = 3'))
        with self.assertRaises(data.NoGo):data.profile(p)
    def test_atomic_permissions(self):
        p=self.p/'state';data.atomic(p,'old');data.atomic(p,'new')
        self.assertEqual(p.read_text(),'new');self.assertEqual(p.stat().st_mode&0o777,0o600)
    def test_atomic_refuses_symlink(self):
        p=self.p/'link';p.symlink_to(self.p/'elsewhere')
        with self.assertRaises(data.NoGo):data.atomic(p,'blocked')
    def test_restore_preserves_private_key_and_peers(self):
        p=self.file('awg0.conf',data.render(self.server()))
        result=data.restore_clients(self.c,p)
        self.assertEqual(result[0][1]['PrivateKey'],self.server()[0][1]['PrivateKey'])
        self.assertEqual(result[1:],self.server()[1:])
    def test_restore_rejects_hooks(self):
        p=self.file('awg0.conf',data.render(self.server({'PostUp':'echo forbidden'})))
        with self.assertRaises(data.NoGo):data.restore_clients(self.c,p)
    def test_restore_rejects_duplicate_addresses(self):
        s=self.server();s.append(('Peer',{'PublicKey':dummy_key(3),'AllowedIPs':'10.77.77.2/32'}))
        p=self.file('awg0.conf',data.render(s))
        with self.assertRaises(data.NoGo):data.restore_clients(self.c,p)
    def test_restore_rejects_split_or_broad_peer(self):
        s=self.server();s[1][1]['AllowedIPs']='0.0.0.0/0'
        with self.assertRaises(data.NoGo):data.restore_clients(self.c,self.file('awg0.conf',data.render(s)))
    def test_a_rewrites_only_transit_and_preserves_private(self):
        p=self.file('profile',(ROOT/'config/transit-profile-B.conf.example').read_text())
        self.c.update(TRANSIT_PROFILE_FILE=str(p),EXIT_TRANSIT_PUBLIC_KEY=dummy_key(4))
        s=self.server({'Address':self.c['ENTRY_AWG1_ADDR'],'ListenPort':'60334','PostDown':'ip rule del pref 100'})
        old=self.file('awg1.conf',data.render(s))
        out=data.render_transit(self.c,dummy_key(7),old)
        self.assertEqual(out[0][1]['PrivateKey'],s[0][1]['PrivateKey'])
        self.assertNotIn('PostDown',out[0][1])
        self.assertEqual(out[1][1]['PublicKey'],self.c['EXIT_TRANSIT_PUBLIC_KEY'])
    def test_a_transit_profile_mismatch_blocks(self):
        p=self.file('profile',(ROOT/'config/transit-profile-B.conf.example').read_text())
        self.c.update(TRANSIT_PROFILE_FILE=str(p),EXIT_TRANSIT_PUBLIC_KEY=dummy_key(4))
        old=self.file('awg1.conf',data.render(self.server({'S3':'13','Address':self.c['ENTRY_AWG1_ADDR'],'ListenPort':'60334'})))
        with self.assertRaisesRegex(data.NoGo,'profile'):data.render_transit(self.c,dummy_key(),old)
    def test_a_old_psk_cannot_be_silently_removed(self):
        p=self.file('profile',(ROOT/'config/transit-profile-B.conf.example').read_text())
        self.c.update(TRANSIT_PROFILE_FILE=str(p),EXIT_TRANSIT_PUBLIC_KEY=dummy_key(4))
        s=self.server({'Address':self.c['ENTRY_AWG1_ADDR'],'ListenPort':'60334'});s[1][1]['PresharedKey']=dummy_key(5)
        with self.assertRaisesRegex(data.NoGo,'PSK'):data.render_transit(self.c,dummy_key(),self.file('awg1.conf',data.render(s)))
    def test_sqlite_online_copy_integrity_and_rows(self):
        import sqlite3
        a=self.p/'source.sqlite';b=self.p/'copy.sqlite'
        db=sqlite3.connect(a);db.execute('CREATE TABLE daily(day TEXT, rx INT)');db.execute("INSERT INTO daily VALUES ('test',42)");db.commit();a.chmod(0o600)
        data.sqlite_copy(a,b)
        other=sqlite3.connect(b)
        self.assertEqual(other.execute('SELECT * FROM daily').fetchall(),[('test',42)])
        self.assertEqual(other.execute('PRAGMA integrity_check').fetchone()[0],'ok')
        db.close();other.close()
    def test_rollback_put_restores_exact_file(self):
        tx=self.p/'tx';tx.mkdir();src=self.file('new','replacement');dst=self.file('old','original')
        subprocess.run([sys.executable,str(ROOT/'common/data.py'),'put',str(tx),str(src),str(dst)],check=True)
        # Не вызываем actual undo (systemctl); проверяем durable inverse manifest.
        record=json.loads((tx/'undo.jsonl').read_text())
        self.assertEqual(Path(record['old']).read_text(),'original');self.assertTrue(record['existed'])
        self.assertEqual(dst.read_text(),'replacement')
    def test_rollback_retry_skips_successful_inverses(self):
        tx=self.p/'tx';tx.mkdir();(tx/'undo.jsonl').write_text(json.dumps({'command':['fixture-inverse']})+'\n')
        with patch.object(data.subprocess,'run',return_value=subprocess.CompletedProcess([],0)) as runner:
            for _ in range(2):
                with patch.object(sys,'argv',['data.py','undo',str(tx)]):data.main()
        self.assertEqual(sum(call.args[0]==['fixture-inverse'] for call in runner.call_args_list),1)
        self.assertEqual(json.loads((tx/'undo-completed.json').read_text()),[0])
    def test_bash_syntax_all_scripts(self):
        for p in ROOT.rglob('*.sh'):
            with self.subTest(script=str(p.relative_to(ROOT))): subprocess.run(['bash','-n',str(p)],check=True)
    def test_internal_scripts_default_no_mutation(self):
        for name in ('runtime.sh','rollback-runtime.sh'):
            p=subprocess.run(['bash',str(ROOT/'common'/name)],capture_output=True,text=True)
            self.assertEqual(p.returncode,0);self.assertIn('DRY-RUN',p.stdout)
    def test_default_dry_run_dispatch_has_no_mutations(self):
        c=fixture();config=self.file('config.env','\n'.join(k+'='+json.dumps(v) for k,v in c.items())+'\n');inventory=self.file('inventory.env','# no overrides\n')
        fake=self.p/'bin';fake.mkdir();log=self.p/'calls';fakepy=fake/'python3'
        fakepy.write_text('#!'+sys.executable+'\n'+
            'import os,sys,subprocess\n'+
            'from pathlib import Path\n'+
            'if sys.argv[1].endswith("checks.py"):\n'+
            ' with open(os.environ["CALL_LOG"],"a") as f:f.write(sys.argv[2]+"\\n")\n'+
            ' sys.exit(0)\n'+
            'os.execv('+repr(sys.executable)+',["python3"]+sys.argv[1:])\n')
        fakepy.chmod(0o750)
        for binary in ('iptables','ip6tables','iptables-save','ip6tables-save','nft','awg','awg-quick','modinfo','ping','ss','tar','flock','systemctl','systemd-analyze','apt-get','add-apt-repository','ip','modprobe'):
            p=fake/binary;p.write_text('#!/bin/bash\necho "MUTATION_OR_UNEXPECTED_COMMAND $0 $*" >> "$CALL_LOG"\nexit 87\n');p.chmod(0o750)
        env=os.environ.copy();env.update(PATH=str(fake)+':'+env['PATH'],CALL_LOG=str(log),PYTHONDONTWRITEBYTECODE='1')
        for action in ('preflight','backup','keys','B-setup-entry','B-clients','B-commit','verify'):
            p=subprocess.run(['bash',str(ROOT/'common/engine.sh'),action,'--config',str(config),'--inventory',str(inventory)],env=env,capture_output=True,text=True)
            self.assertEqual(p.returncode,0,(action,p.stderr));self.assertIn('DRY-RUN',p.stdout)
        self.assertNotIn('MUTATION',log.read_text())
    def test_apply_requires_root_before_mutation(self):
        if os.geteuid()==0: self.skipTest('Запуск этого теста под root не предусмотрен')
        c=fixture();config=self.file('c.env','\n'.join(k+'='+json.dumps(v) for k,v in c.items())+'\n');inv=self.file('i.env','# empty\n')
        p=subprocess.run(['bash',str(ROOT/'common/engine.sh'),'B-setup-entry','--config',str(config),'--inventory',str(inv),'--apply','--confirm','APPLY B-setup-entry'],capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertIn('root',p.stderr)
    def test_dry_and_apply_mutually_exclusive_both_orders(self):
        for flags in (['--dry-run','--apply'],['--apply','--dry-run']):
            p=subprocess.run(['bash',str(ROOT/'common/engine.sh'),'B-setup-entry',*flags],capture_output=True,text=True)
            self.assertEqual(p.returncode,2);self.assertIn('одновременно',p.stderr)
    def test_new_empty_table100_is_not_an_error(self):
        with patch.object(checks,'run',return_value=subprocess.CompletedProcess([],2,'[]','Error: ipv4: FIB table does not exist.')):
            self.assertEqual(checks.table100(),[])
    def test_table100_permission_failure_is_not_masked(self):
        with patch.object(checks,'run',return_value=subprocess.CompletedProcess([],2,'','Operation not permitted')):
            with self.assertRaises(data.NoGo):checks.table100()
    def test_restore_refuses_server_identity_replacement(self):
        a=self.file('a.conf',data.render(self.server()));b=self.file('b.conf',data.render(self.server({'PrivateKey':dummy_key(8)})))
        p=subprocess.run([sys.executable,str(ROOT/'common/data.py'),'compare-identity',str(a),str(b)],capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertNotIn(dummy_key(8),p.stderr)
    def test_kernel_roundtrip_missing_s3_blocks(self):
        a=self.file('a.conf',data.render(self.server()));s=self.server();del s[0][1]['S3'];b=self.file('b.conf',data.render(s))
        p=subprocess.run([sys.executable,str(ROOT/'common/data.py'),'probe-result',str(a),str(b)],capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertIn('S3',p.stderr)
    def test_enroll_idempotent_and_full_tunnel_with_real_awg_pubkey(self):
        binary=os.environ.get('PACO_TEST_AWG_BIN')
        if not binary: self.skipTest('Опционально укажите PACO_TEST_AWG_BIN для реального userspace tool')
        fake=self.p/'bin';fake.mkdir();(fake/'awg').symlink_to(binary)
        cfg=self.file('c.env','\n'.join(k+'='+json.dumps(v) for k,v in self.c.items())+'\n');inv=self.file('i.env','# empty\n')
        server=self.file('server.conf',data.render(self.server()[:1]));clients=self.p/'clients'
        secure=data.secure_file
        with patch.dict(os.environ,{'PATH':str(fake)+':'+os.environ['PATH']}),patch.object(data,'secure_file',side_effect=lambda p,root=False:secure(p,root=False)):
            for name in ('testpaco','testpaco','another'):
                with patch.object(sys,'argv',['data.py','enroll',str(cfg),str(inv),str(server),name,str(clients)]):data.main()
        s=data.parse_awg(server);self.assertEqual(len(s),3)
        self.assertEqual(len({p['PublicKey'] for n,p in s[1:]}),2)
        self.assertEqual({p['AllowedIPs'] for n,p in s[1:]},{'10.77.77.2/32','10.77.77.3/32'})
        profile=data.parse_awg(clients/'testpaco.conf')
        self.assertEqual(profile[1][1]['AllowedIPs'],'0.0.0.0/0, ::/0')
        self.assertEqual(profile[0][1]['S3'],'12');self.assertEqual(profile[0][1]['MTU'],'1380')

if __name__=='__main__':unittest.main(verbosity=2)
