"""Linux Audit 脱敏采集器：不读取/保存 EXECVE 参数或 PROCTITLE。

只接受指定规则 key 和 UID。系统调用、PATH 和 SOCKADDR 被合并为稳定
事件；读取位点与 outbox 入队在一个 SQLite 事务内提交。
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import time
from datetime import datetime,timezone
from endpoint.config import load
from endpoint.outbox import Outbox

HEADER=re.compile(r'\btype=(\w+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\)')
FIELDS=re.compile(r'(\w+)=("[^"]*"|\S+)')
# x86_64 only: rule installation is explicitly arch=b64.
SYSCALLS={'59':'process_start','322':'process_start','42':'network_connect',
          '2':'file_access','257':'file_access','437':'file_access'}


def decode(value):
    if value.startswith('"') and value.endswith('"'):return value[1:-1]
    if len(value)%2==0 and value and all(c in '0123456789abcdefABCDEF' for c in value):
        try:return bytes.fromhex(value).decode('utf-8')
        except (ValueError,UnicodeError):return value
    return value


def record(line):
    match=HEADER.search(line)
    if not match:return None
    kind,stamp,serial=match.groups()
    if kind not in {'SYSCALL','PATH','CWD','SOCKADDR','EOE'}:return (stamp,serial,kind,{})
    allowed={'arch','syscall','success','exit','pid','ppid','uid','exe','key','name','nametype','cwd','saddr','item'}
    data={k:decode(v) if k in {'exe','key','name','cwd'} else v.strip('"') for k,v in FIELDS.findall(line[match.end():]) if k in allowed}
    return stamp,serial,kind,data


def address(value):
    try:
        data=bytes.fromhex(value);family=int.from_bytes(data[:2],'little');port=int.from_bytes(data[2:4],'big')
        if family==2 and len(data)>=8:return {'host':str(ipaddress.ip_address(data[4:8])),'port':port}
        if family==10 and len(data)>=24:return {'host':str(ipaddress.ip_address(data[8:24])),'port':port}
    except (ValueError,IndexError):pass
    return None


def normalize(records,*,uid,keys,boot_id):
    syscall=next((r[3] for r in records if r[2]=='SYSCALL'),None)
    if not syscall or syscall.get('uid')!=str(uid) or syscall.get('key') not in keys or syscall.get('arch')!='c000003e':return []
    event_type=SYSCALLS.get(syscall.get('syscall'))
    if not event_type:return []
    stamp,serial=records[0][:2]
    try:
        process={'pid':int(syscall['pid']),'ppid':int(syscall['ppid']),'executable':syscall.get('exe')}
        occurred=datetime.fromtimestamp(float(stamp),timezone.utc).isoformat()
    except (KeyError,ValueError,OverflowError):return []
    resources=[None]
    if event_type=='file_access':
        resources=[{'path':r[3]['name']} for r in records if r[2]=='PATH' and r[3].get('name') and r[3].get('nametype')!='PARENT'] or [None]
    elif event_type=='network_connect':
        resources=[address(r[3].get('saddr','')) for r in records if r[2]=='SOCKADDR'] or [None]
    events=[]
    for index,resource in enumerate(resources):
        digest=hashlib.sha256(f'{boot_id}:{stamp}:{serial}:{index}'.encode()).hexdigest()[:32]
        event={'event_id':'audit_'+digest,'event_type':event_type,'occurred_at':occurred,'process':process,
            'resource':resource,'action':{'process_start':'exec','file_access':'open','network_connect':'connect'}[event_type],
            'result':'success' if syscall.get('success')=='yes' else 'in_progress' if event_type=='network_connect' and syscall.get('exit')=='-115' else 'failed','sequence':int(serial),
            'evidence_refs':[{'kind':'linux_audit','uri':f'audit:{boot_id}:{stamp}:{serial}'}]}
        events.append(event)
    return events


def is_own_telemetry_pid(pid):
    """不要把 reporter 上报本身再次变成待上报网络事件，避免反馈循环。"""
    try:
        argv=(Path('/proc')/str(pid)/'cmdline').read_bytes().split(b'\0')
        return any(argv[i]==b'-m' and argv[i+1] in {b'endpoint.flush',b'endpoint.audit',b'endpoint.hook'} for i in range(len(argv)-1))
    except OSError:
        return False


def collect_once(config,*,settled=False):
    source=Path(config['audit_log']);state=Path(config['state_dir']);box=Outbox(state,config.get('max_records',10000))
    try:
        box.db.execute('CREATE TABLE IF NOT EXISTS collector_cursors (source TEXT PRIMARY KEY,device INTEGER,inode INTEGER,offset INTEGER)')
        cursor=box.db.execute('SELECT device,inode,offset FROM collector_cursors WHERE source=?',(str(source),)).fetchone()
        selected=source
        current=source.stat()
        rotation_gap=False
        if cursor and (cursor['device'],cursor['inode'])!=(current.st_dev,current.st_ino):
            previous=None
            for candidate in source.parent.glob(source.name+'.*'):
                try:
                    old=candidate.stat()
                    if (old.st_dev,old.st_ino)==(cursor['device'],cursor['inode']):previous=(candidate,old);break
                except OSError:continue
            if previous and cursor['offset']<previous[1].st_size:
                selected=previous[0]
            elif previous is None:
                rotation_gap=True
        with selected.open('rb') as stream:
            stat=os.fstat(stream.fileno())
            offset=cursor['offset'] if cursor and cursor['device']==stat.st_dev and cursor['inode']==stat.st_ino and cursor['offset']<=stat.st_size else 0
            stream.seek(offset);raw=stream.read(1024*1024)
        if not raw:return {'events':0,'bytes':0,'offset':offset}
        # Never checkpoint a partial text record.
        boundary=raw.rfind(b'\n')+1
        if boundary==0:raise ValueError('audit_record_exceeds_read_limit')
        raw=raw[:boundary];groups={};positions={};position=offset
        for line in raw.splitlines(keepends=True):
            parsed=record(line.decode('utf-8','replace'))
            if parsed:
                key=parsed[:2];groups.setdefault(key,[]).append(parsed);positions.setdefault(key,position)
            position+=len(line)
        end=offset+len(raw)
        if groups and not settled:
            last=next(reversed(groups))
            if not any(r[2]=='EOE' for r in groups[last]):
                end=positions[last];groups.pop(last)
        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        records=[]
        excluded=0
        for rows in groups.values():
            syscall=next((r[3] for r in rows if r[2]=='SYSCALL'),{})
            if is_own_telemetry_pid(syscall.get('pid')):
                excluded+=1
                continue
            for event in normalize(rows,uid=config['audit_uid'],keys=set(config['audit_keys']),boot_id=boot_id):
                batch={'collector_id':'linux-audit-v1','events':[event]}
                records.append(('linux-audit-v1:'+event['event_id'],'/api/v1/runtime-events:batch',batch))
        # enqueue_many opens one transaction; checkpoint must commit in that same transaction.
        with box.db:
            box.db.execute('BEGIN IMMEDIATE')
            box.reserve(records)
            if box.path.stat().st_size>32*1024*1024:raise RuntimeError('outbox_disk_capacity_exceeded')
            for rid,endpoint,payload in records:
                now=time.time();box.db.execute('INSERT OR IGNORE INTO outbox (record_id,endpoint,payload,created_at,updated_at) VALUES (?,?,?,?,?)',
                    (rid,endpoint,json.dumps(payload),now,now))
            box.db.execute('INSERT OR REPLACE INTO collector_cursors VALUES (?,?,?,?)',(str(source),stat.st_dev,stat.st_ino,end))
        return {'events':len(records),'bytes':end-offset,'offset':end,'own_telemetry_excluded':excluded,'rotation_gap':rotation_gap}
    finally:box.close()


def main():
    p=argparse.ArgumentParser();p.add_argument('--once',action='store_true');args=p.parse_args();config=load()
    while True:
        try:
            result=collect_once(config,settled=False)
            if not result['bytes']:
                time.sleep(.2);result=collect_once(config,settled=True)
            print(json.dumps({'component':'linux-audit-v1',**result}),flush=True)
        except Exception as exc:
            print(json.dumps({'component':'linux-audit-v1','error_type':type(exc).__name__}),flush=True)
        if args.once:break
        time.sleep(2)


if __name__=='__main__':main()
