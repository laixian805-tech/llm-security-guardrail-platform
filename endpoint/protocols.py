"""版本化产品协议到中性事件，端点不依赖控制面或第三方包。"""
import json

EVENTS = {'SessionStart': 'session_start', 'PreToolUse': 'pre_tool_use',
          'PostToolUse': 'post_tool_use', 'SessionEnd': 'session_end'}
COMMON = {'hook_event_name', 'session_id', 'transcript_path', 'cwd', 'permission_mode', 'model', 'agent_id', 'agent_type', 'effort'}
EXTRA = {'SessionStart': {'source'}, 'SessionEnd': {'reason'},
         'PreToolUse': {'tool_name', 'tool_input', 'tool_use_id', 'turn_id'},
         'PostToolUse': {'tool_name', 'tool_input', 'tool_use_id', 'tool_response', 'turn_id', 'duration_ms'}}


def parse(product, payload):
    if product not in ('codex', 'claude-code') or not isinstance(payload, dict):
        raise ValueError('unsupported_product_or_payload')
    name = payload.get('hook_event_name')
    if name not in EVENTS:
        raise ValueError('unsupported_event')
    if set(payload) - COMMON - EXTRA[name]:
        raise ValueError('unknown_protocol_fields')
    if not isinstance(payload.get('session_id'), str) or not payload['session_id']:
        raise ValueError('session_id_required')
    tool = name in ('PreToolUse', 'PostToolUse')
    if tool and (not isinstance(payload.get('tool_name'), str) or not isinstance(payload.get('tool_input'), dict)):
        raise ValueError('invalid_tool_payload')
    call_id = payload.get('tool_use_id')
    if call_id is not None and (not isinstance(call_id, str) or not call_id):
        raise ValueError('invalid_tool_call_id')
    return {'event': name, 'hook_event_type': EVENTS[name], 'session_id': payload['session_id'],
            'occurred_at': None, 'tool_name': payload.get('tool_name') if tool else None,
            'tool_call_id': call_id if tool else None, 'params': payload.get('tool_input', {}) if tool else {},
            'product_result': (payload['tool_response'] if isinstance(payload.get('tool_response'), str)
              else json.dumps(payload.get('tool_response'), ensure_ascii=False, sort_keys=True)) if name == 'PostToolUse' else None}


def directive(event, decision='not_applicable', reason=''):
    if event != 'pre_tool_use' or decision == 'not_applicable':
        return ''
    if decision not in ('allow', 'ask', 'deny'):
        raise ValueError('invalid_decision')
    return json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse',
        'permissionDecision': decision, 'permissionDecisionReason': reason}})
