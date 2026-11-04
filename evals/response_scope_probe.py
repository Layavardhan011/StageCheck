"""Owner response-hook REQUEST §6/§7: excluded-citation interaction, fixture only."""
import tempfile,json
from pathlib import Path
from test_response import Hook,HEADS,encode
def main():
    case=Hook('test_scope_and_authority_no_repository') if hasattr(Hook,'test_scope_and_authority_no_repository') else Hook('test_both_agent_shapes_and_no_claims');case.setUp()
    try:
        p=case.root/'RWA/previous';p.mkdir();file=p/'excluded.txt';file.write_text('excluded fixture')
        answer=case.backed('excluded fixture inspected')
        c=case.data['claims'][0]['citations'][0];c.update(path=str(file),lines=[1,1],quote='excluded fixture')
        from common import digest
        c['sha256']=digest(file.read_bytes());case.path.write_bytes(encode(case.data))
        output=case.submit(answer)
        record=case.records()[-1]
        print(json.dumps({'decision':record['decision'],'output':output,'record':record}))
        if record['attempt_path']:
            from common import load
            print(json.dumps(load(Path(record['attempt_path'])/'verdict.json')))
        else:
            folders=list((case.root/'evidence/stagecheck').glob('*/*/verdict.json'))
            from common import load
            for file in folders:print(json.dumps(load(file)))
    finally:case.doCleanups()
    return 0
if __name__=='__main__':raise SystemExit(main())
