"""产品执行路径只做本地持久写入，不等待网络和模型。"""
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone
from endpoint.config import load
from endpoint.outbox import Outbox, enqueue
from endpoint.protocols import parse, directive
from endpoint.redaction import summarize


def stable(*parts):
    return uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(parts)).hex


def capture(config, product, payload, *, now=None):
    event = parse(product, payload)
    stamp = now or datetime.now(timezone.utc).isoformat()
    version = config['product_versions'][product]
    fingerprint = config.get('binary_fingerprints', {}).get(product)
    if fingerprint:
        for file in fingerprint.get('files', [fingerprint]):
            target = Path(file['path'])
            try:
                stat = target.stat()
                current = [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns]
            except OSError:
                current = None
            if current != file['stat']:
                version = 'unverified-changed'
            elif 'sha256' in file:
                try:
                    file_hash = hashlib.sha256(target.read_bytes()).hexdigest()
                except OSError:
                    file_hash = None
                if file_hash != file['sha256']:
                    version = 'unverified-changed'
    execution_id = 'exec_'+stable(product, event['session_id'])
    outbox = Outbox(config['state_dir'], config.get('max_records', 10000))
    try:
        started = outbox.session_start(execution_id) or stamp
        execution = {'execution_id': execution_id, 'product': product, 'product_version': version,
            'session_id': event['session_id'], 'started_at': started, 'outcome': 'running'}
        records = [(execution_id+':start', '/api/v1/executions', execution)]
        decision = 'not_applicable'
        reason = 'ASGP endpoint rule'
        if event['hook_event_type'] == 'pre_tool_use' and config.get('fail_mode') == 'deny':
            if version == 'unverified-changed':
                decision = 'deny'
                reason = 'ASGP fail-closed: product binary verification failed (unverified-changed)'
            else:
                verified = config.get('verified_decisions', {}).get(product)
                if verified != version:
                    raise ValueError('decision_protocol_not_verified_for_version')
                raw = json.dumps(event['params'], ensure_ascii=False)
                decision = 'deny' if any(s in raw for s in config.get('deny_patterns', [])) else 'allow'
                if decision == 'allow' and any(s in raw for s in config.get('ask_patterns', [])):
                    if config.get('approval_mode') == 'control_plane':
                        from endpoint.approval import request_approval
                        decision, reason = request_approval(config, product, version, event)
                    elif product == 'codex':
                        decision = 'deny'
                        reason = 'ASGP confirmation unsupported for Codex 0.166.0; denied'
                    else:
                        decision = 'ask'
        if event['tool_name']:
            call = event['tool_call_id'] or uuid.uuid4().hex
            intent_id = 'intent_'+stable(execution_id, call)
            summary, digest = summarize(event['params'])
            intent = {'intent_id': intent_id, 'tool_call_id': event['tool_call_id'],
                'tool_name': event['tool_name'], 'hook_event_type': event['hook_event_type'],
                'decision': decision, 'decision_reason': reason if decision != 'not_applicable' else None,
                'params_summary': summary, 'params_sha256': digest, 'redaction_applied': True,
                'occurred_at': stamp, 'ended_at': stamp if event['event'] == 'PostToolUse' else None,
                'product_result': 'observed' if event['event'] == 'PostToolUse' else None,
                'source_kind': os.environ.get('ASGP_SOURCE_KIND') or None,
                'source_ref': os.environ.get('ASGP_SOURCE_REF') or None}
            records.append((intent_id+':'+event['event'], '/api/v1/executions/'+execution_id+'/intents', intent))
            if config.get('runtime_anchors') and event['event']=='PreToolUse':
                pid=os.getppid()
                product_pid=None
                for _ in range(8):
                    try:
                        status=Path('/proc')/str(pid)/'status'
                        fields=dict(line.split(':',1) for line in status.read_text().splitlines() if ':' in line)
                        name=fields.get('Name','').strip()
                        parent=int(fields['PPid'])
                        cmdline=''
                        if product=='qwen-code' and name not in {'codex','claude','claude.exe','qwen'}:
                            try:
                                cmdline=(Path('/proc')/str(pid)/'cmdline').read_bytes().decode('utf-8','ignore')
                            except OSError:
                                cmdline=''
                        if name in {'codex','claude','claude.exe','qwen'} or (product=='qwen-code' and any(part == 'qwen' or part.endswith('/qwen') or '@qwen-code' in part or 'cli-entry.js' in part for part in cmdline.split('\x00') if part)):
                            product_pid=(pid,parent,'qwen' if product=='qwen-code' else name);break
                        if parent<=1:break
                        pid=parent
                    except (OSError,KeyError,ValueError):break
                if product_pid:
                    anchor={'event_id':'anchor_'+stable(execution_id,call),'execution_id':execution_id,
                        'intent_ref':intent_id,'event_type':'hook_anchor','occurred_at':stamp,
                        'process':{'pid':product_pid[0],'ppid':product_pid[1],'executable':product_pid[2]},
                        'action':'tool_context','result':'observed',
                        'evidence_refs':[{'kind':'hook_call','uri':intent_id}]}
                    records.append((anchor['event_id'],'/api/v1/runtime-events:batch',
                        {'collector_id':product+'-hook-v1','events':[anchor]}))
        if event['event'] == 'SessionEnd':
            execution = dict(execution, ended_at=stamp, outcome='completed')
            records.append((execution_id+':end', '/api/v1/executions', execution))
        enqueue(outbox, records, session=(execution_id, started))
        return directive(event['hook_event_type'], decision, reason)
    finally:
        outbox.close()


def main():
    product = sys.argv[1] if len(sys.argv) > 1 else ''
    event_id = uuid.uuid4().hex
    cfg = None
    parsed = None
    try:
        cfg = load()
        raw = sys.stdin.buffer.read(8*1024*1024+1)
        if len(raw) > 8*1024*1024:
            raise ValueError('body_too_large')
        parsed = json.loads(raw)
        output = capture(cfg, product, parsed)
        if output:
            print(output)
    except Exception as exc:
        # Never put product input, paths, credentials or exception values in logs.
        print(json.dumps({'component':'asgp_hook','event_id':event_id,'error_type':type(exc).__name__}), file=sys.stderr)
        fail_mode = cfg.get('fail_mode') if isinstance(cfg, dict) else None
        if fail_mode is None:
            try:
                cfg_path = Path(os.environ.get('ASGP_ENDPOINT_CONFIG', str(Path.home()/'.asgp/endpoint/config.json')))
                raw_cfg = json.loads(cfg_path.read_text())
                if isinstance(raw_cfg, dict):
                    fail_mode = raw_cfg.get('fail_mode')
            except Exception:
                fail_mode = None
        if fail_mode is None:
            fail_mode = os.environ.get('ASGP_FAIL_MODE')
        hook_name = parsed.get('hook_event_name') if isinstance(parsed, dict) else None
        if fail_mode == 'deny' and hook_name in (None, 'PreToolUse'):
            print(directive('pre_tool_use', 'deny', 'ASGP fail-closed ('+type(exc).__name__+')'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
