"""产品执行路径只做本地持久写入，不等待网络和模型。"""
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone
from endpoint.config import load
from endpoint.outbox import Outbox
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
            try:
                stat = Path(file['path']).stat()
                current = [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns]
            except OSError:
                current = None
            if current != file['stat']:
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
        if event['hook_event_type'] == 'pre_tool_use' and config.get('fail_mode') == 'deny' and version != 'unverified-changed':
            verified = config.get('verified_decisions', {}).get(product)
            if verified != version:
                raise ValueError('decision_protocol_not_verified_for_version')
            raw = json.dumps(event['params'], ensure_ascii=False)
            decision = 'deny' if any(s in raw for s in config.get('deny_patterns', [])) else 'allow'
            if decision == 'allow' and any(s in raw for s in config.get('ask_patterns', [])):
                if product == 'codex':
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
                'product_result': 'observed' if event['event'] == 'PostToolUse' else None}
            records.append((intent_id+':'+event['event'], '/api/v1/executions/'+execution_id+'/intents', intent))
        if event['event'] == 'SessionEnd':
            execution = dict(execution, ended_at=stamp, outcome='completed')
            records.append((execution_id+':end', '/api/v1/executions', execution))
        outbox.enqueue_many(records, session=(execution_id, started))
        return directive(event['hook_event_type'], decision, reason)
    finally:
        outbox.close()


def main():
    product = sys.argv[1] if len(sys.argv) > 1 else ''
    event_id = uuid.uuid4().hex
    try:
        raw = sys.stdin.buffer.read(8*1024*1024+1)
        if len(raw) > 8*1024*1024:
            raise ValueError('body_too_large')
        output = capture(load(), product, json.loads(raw))
        if output:
            print(output)
    except Exception as exc:
        # Never put product input, paths, credentials or exception values in logs.
        print(json.dumps({'component':'asgp_hook','event_id':event_id,'error_type':type(exc).__name__}), file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
