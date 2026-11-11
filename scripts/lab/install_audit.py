from pathlib import Path
import subprocess,os,pwd,sqlite3,json
h=Path('/home/agentsec-lab');watched=h/'lab/asgp-p23'
rule=f'-w {watched} -p rwa -k asgp_p2_files\n'
rules=Path('/etc/audit/rules.d/98-asgp-p2.rules')
if rules.exists() and rules.read_text()!=rule:raise SystemExit('existing rule differs; refusing overwrite')
rules.write_text(rule);rules.chmod(0o640)
current=subprocess.check_output(['auditctl','-l'],text=True)
if 'asgp_p2_files' not in current:subprocess.run(['auditctl','-w',str(watched),'-p','rwa','-k','asgp_p2_files'],check=True)
state=h/'.asgp/endpoint';source=Path('/var/log/audit/audit.log');stat=source.stat()
c=sqlite3.connect(str(state/'outbox.db'))
c.execute('CREATE TABLE IF NOT EXISTS collector_cursors (source TEXT PRIMARY KEY,device INTEGER,inode INTEGER,offset INTEGER)')
c.execute('INSERT OR IGNORE INTO collector_cursors VALUES (?,?,?,?)',(str(source),stat.st_dev,stat.st_ino,stat.st_size));c.commit();c.close()
unit='''[Unit]
Description=ASGP Linux Audit collector for test UID
After=auditd.service network.target
Requires=auditd.service
[Service]
Type=simple
User=agentsec-lab
Group=agentsec-lab
SupplementaryGroups=adm
WorkingDirectory=/home/agentsec-lab/.asgp/source
Environment=ASGP_ENDPOINT_CONFIG=/home/agentsec-lab/.asgp/endpoint/config.json
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 -m endpoint.audit
Restart=on-failure
RestartSec=5
UMask=0077
MemoryMax=96M
CPUQuota=10%
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/home/agentsec-lab/.asgp/endpoint
ProtectHome=read-only
PrivateTmp=true
[Install]
WantedBy=multi-user.target
'''
Path('/etc/systemd/system/asgp-audit-collector.service').write_text(unit)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','asgp-audit-collector.service'],check=True)
print('ASGP audit collector installed; existing UID-scoped exec/connect rules reused; private watch only')
