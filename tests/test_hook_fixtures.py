"""真实产品 fixture 的三类决策编码，以及端侧/控制面映射一致性。"""
import json
from pathlib import Path
import pytest
from adapters.products.base import HookDirective, UnsupportedHookProtocol
from domain import IntentDecision
from products.registry import ProductCatalog
from endpoint.protocols import parse, directive


@pytest.mark.parametrize('product,version',[('codex','0.166.0'),('claude-code','2.1.152')])
@pytest.mark.parametrize('event',['SessionStart','PreToolUse','PostToolUse','SessionEnd'])
def test_recorded_payload_and_endpoint_mapping_agree(product,version,event):
    root=Path(__file__).parent/'fixtures/hooks'/product/version
    payload=json.loads((root/(event+'.json')).read_text())
    adapter=ProductCatalog().get(product)
    neutral=adapter.parse_hook_input(payload)
    assert neutral.neutral()==parse(product,payload)
    for decision in [IntentDecision.ALLOW,IntentDecision.ASK,IntentDecision.DENY]:
        if product=="codex" and event=="PreToolUse" and decision is IntentDecision.ASK:
            with pytest.raises(UnsupportedHookProtocol):
                adapter.render_directive(neutral,HookDirective(decision=decision,reason="rule"))
            continue
        response=adapter.render_directive(neutral,HookDirective(decision=decision,reason='rule'))
        assert response.exit_code==0
        expected=directive(neutral.hook_event_type.value,decision.value,'rule')
        assert (json.loads(response.stdout) if response.stdout else None)==(json.loads(expected) if expected else None)
