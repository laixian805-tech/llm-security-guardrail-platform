#!/usr/bin/env python3
"""离线标注小轨迹：完整归因管道实际输出，不能推导生产准确率。"""
import json,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'backend'));sys.path.insert(0,str(ROOT))
from storage.repositories import Storage,DeviceIdentityRepository
from services.ingestion_service import IngestionService
from services.attribution_service import AttributionService
from adapters.products.capabilities import PRODUCT_VERSIONS


def main():
    with tempfile.TemporaryDirectory(prefix='asgp-attribution-benchmark-') as tmp:
        storage=Storage(Path(tmp)/'trace.db');devices=DeviceIdentityRepository(storage)
        device,_=devices.enroll(label='labeled-trace');devices.set_host(device_id=device,host_id='trace-host')
        ingest=IngestionService(storage);stamp='2026-11-11T12:00:00+00:00'
        ingest.execution(device,{'execution_id':'exec','session_id':'s','product':'codex','product_version':PRODUCT_VERSIONS['codex'],'started_at':stamp})
        ingest.intent(device,'exec',{'intent_id':'i','tool_call_id':'call','tool_name':'Bash','hook_event_type':'pre_tool_use','occurred_at':stamp})
        rows=[{'event_id':'hook','execution_id':'exec','intent_ref':'i','event_type':'hook_anchor','occurred_at':stamp,'process':{'pid':100,'ppid':1}},
              {'event_id':'process','event_type':'process_start','occurred_at':stamp,'process':{'pid':101,'ppid':100}},
              {'event_id':'file','event_type':'file_access','occurred_at':stamp,'process':{'pid':101,'ppid':100},'resource':{'path':'/lab/proof'}},
              {'event_id':'network','event_type':'network_connect','occurred_at':stamp,'process':{'pid':101,'ppid':100},'resource':{'host':'127.0.0.1','port':443}},
              {'event_id':'background','event_type':'process_start','occurred_at':stamp,'process':{'pid':999,'ppid':1}}]
        ingest.batch(device,{'collector_id':'labeled-trace','events':rows})
        service=AttributionService(storage);summary=service.correlate('exec');edges=service.list('exec')
        expected={event:'i' for event in ['hook','process','file','network']}
        selected={e['event_id']:e['intent_id'] for e in edges if e['selected']}
        tp=sum(selected.get(k)==v for k,v in expected.items());fp=sum(k not in expected or expected[k]!=v for k,v in selected.items());fn=len(expected)-tp
        result={'dataset':'labeled-small-v1','event_count':5,'expected_associated':4,'expected_unattributed':1,'true_positive':tp,'false_positive':fp,'false_negative':fn,
                'precision':tp/(tp+fp) if tp+fp else 0,'recall':tp/(tp+fn) if tp+fn else 0,'summary':summary,
                'limitation':'Synthetic small trace, not production accuracy; live Audit coverage is evaluated separately.'}
        assert tp==4 and fp==fn==0 and 'background' not in selected
        print(json.dumps(result,indent=2))


if __name__=='__main__':main()
