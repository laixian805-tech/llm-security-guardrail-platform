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


def log_candidates(source):
    """采集顺序：主文件优先，再补最近的轮转文件。

    实时性优先的理由：轮转文件里是历史数据，当前主文件里才是正在发生的事。
    先补旧文件会让"今天的事件"排在几小时甚至十几小时后才入库——实测一次
    轮转后滞后 13 小时，上层所有按时间窗的关联全部落空。

    主文件读完后自然轮到轮转文件（新→旧），缺口仍会被补上，只是排在后面。
    只认 ``audit.log.N`` 形态（排除 .gz/.tmp）。
    """
    rotated = []
    pattern = re.compile(re.escape(source.name) + r'\.\d+$')
    for candidate in source.parent.glob(source.name + '.*'):
        if pattern.match(candidate.name):
            try:
                rotated.append((candidate.stat().st_mtime, str(candidate)))
            except OSError:
                continue
    # 新的轮转文件在前：它刚被切出去，最可能还留着没读完的尾巴。
    return [source] + [Path(name) for _, name in sorted(rotated, reverse=True)]


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
        existing={row[1] for row in box.db.execute('PRAGMA table_info(collector_cursors)')}
        if existing and 'updated_at' not in existing:
            # 旧版主键是 source，无法表达"每个轮转文件一个位置"。重建表：
            # 游标丢了只会重读一遍，outbox 按 event_id 去重，不会重复入库。
            box.db.execute('DROP TABLE collector_cursors')
        box.db.execute('CREATE TABLE IF NOT EXISTS collector_cursors ('
                       'source TEXT NOT NULL, inode INTEGER NOT NULL, device INTEGER NOT NULL,'
                       ' offset INTEGER NOT NULL, updated_at REAL NOT NULL,'
                       ' PRIMARY KEY (source, inode))')
        cursors={row['inode']:row['offset'] for row in box.db.execute(
            'SELECT inode,offset FROM collector_cursors WHERE source=?',(str(source),))}
        selected=stat=None;offset=0;home=None
        # 游标里的 inode 已不在磁盘上 = 有轮转文件被删除，确实丢了数据。
        # 放在选择之前算，保证"主文件没新数据"这条路径也能如实上报。
        live={p.stat().st_ino for p in log_candidates(source) if p.exists()}
        rotation_gap=any(inode not in live for inode in cursors)
        # 每个 inode 记各自的 offset。原先以 source 为游标主键，轮转后旧 offset
        # 被带到新文件上；一旦越界就永远读不到数据，表现为事件时间静默停在几小时前。
        for path in log_candidates(source):
            try:candidate=path.stat()
            except OSError:continue
            position=cursors.get(candidate.st_ino,0)
            if position<0 or position>candidate.st_size:position=0
            if position>=candidate.st_size:
                # 读完了。主文件的位置记下来用于"暂时没有新数据"的回报，
                # 但不能就此返回——轮转文件里可能还有没补的尾巴。
                if path==source:home=(path,candidate,position)
                continue
            selected,stat,offset=path,candidate,position
            break
        if selected is None:
            position=home[2] if home else 0
            return {'events':0,'bytes':0,'offset':position,'own_telemetry_excluded':0,'rotation_gap':rotation_gap}
        with selected.open('rb') as stream:
            stream.seek(offset);raw=stream.read(1024*1024)
        if not raw:return {'events':0,'bytes':0,'offset':offset,'own_telemetry_excluded':0,'rotation_gap':rotation_gap}
        # Never checkpoint a partial text record.
        boundary=raw.rfind(b'\n')+1
        if boundary==0:raise ValueError('audit_record_exceeds_read_limit')
        raw=raw[:boundary];groups={};positions={};position=offset
        for line in raw.splitlines(keepends=True):
            parsed=record(line.decode('utf-8','replace'))
            if parsed:
                key=parsed[:2];groups.setdefault(key,[]).append(parsed);positions.setdefault(key,position)
            position+=len(line)
        # 游标绝不能超过被读文件的实际长度：日志轮转时 offset 可能在旧文件上
        # 累加出越界值，一旦保存进去，后续采集会一直在越界位置读不到数据，
        # 表现为"事件时间停在几小时前"。夹紧是最省的兜底。
        end=min(offset+len(raw),stat.st_size)
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
            box.db.execute('INSERT OR REPLACE INTO collector_cursors (source,inode,device,offset,updated_at)'
                ' VALUES (?,?,?,?,?)',(str(source),stat.st_ino,stat.st_dev,end,time.time()))
            if live:
                box.db.execute('DELETE FROM collector_cursors WHERE source=? AND inode NOT IN (%s)'
                    % ','.join('?'*len(live)),(str(source),*sorted(live)))
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
