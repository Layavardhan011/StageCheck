"""Deterministic report rendering; no model, repair text, or product writes."""
from common import *


def render(verdict, verdict_sha256):
    not_done = list(verdict['not_run']) + list(verdict['errors'])
    quality=verdict.get('quality')
    if quality:
        not_done += [name+': '+c['reason']+'; pending '+str(c['pending_count'])
                     for name,c in quality['checks'].items() if c['requested_mode']=='blocking' and c['source']=='report_only']
    not_done += ['unresolved finding: '+d['check_id']+' ('+d['defect_id']+')' for d in verdict['defects']]
    not_done += [c['id']+': command exited '+str(r['exit_status'])+'; see retained command evidence'
                 for c in verdict['checks'] for r in c['commands'] if r['exit_status']]
    first = '; '.join(not_done) if not_done else 'nothing within scope of the checks that ran'
    files = {f['path']: f['sha256'] for c in verdict['checks'] for f in c['files']}
    commands = [r for c in verdict['checks'] for r in c['commands']]
    # The contract requires a short header; the full inventory already resides
    # in the verdict. Prioritize the owner inputs and reconcile exact totals.
    selected=sorted(files.items(),key=lambda item:(item[0] not in verdict['input_hashes'],item[0]))[:8]
    examined = [f'{path} SHA-256 {sha}' for path, sha in selected]
    examined += [f'{json.dumps(r["argv"])} (cwd {r["cwd"]}), exit {r["exit_status"]}, stdout {r["stdout_sha256"]}, stderr {r["stderr_sha256"]}' for r in commands[:3]]
    if not examined:
        examined = ['No file or command evidence was retained']
    examined += [f'Full inventory: verdict SHA-256 {verdict_sha256}; {len(files)} distinct files and {len(commands)} command records']
    result_text = verdict['result'] if verdict['bound'] else 'UNBOUND advisory (' + verdict['result'] + ')'
    limitations = ['not run: ' + item for item in verdict['not_run']]
    limitations += ['error: ' + item for item in verdict['errors']]
    if not verdict['bound']:
        limitations += ['report-only because unbound: ' + d['check_id'] + ' (' + d['defect_id'] + ')'
                        for d in verdict['defects'] if d['mode'] == 'report_only']
    enforcement = ('Enforcement Self-Check: Enforcement is manual; ' + '; '.join(limitations)
                   if limitations else
                   'Enforcement Self-Check: all applied; no unbacked claim; no unproven controlled word. Enforcement is manual.')
    tree = ('dirty (working-tree bytes)' if verdict['dirty'] else 'clean') if 'dirty' in verdict else 'UNKNOWN (legacy or unavailable status)'
    status_identity = verdict.get('status_sha256','UNKNOWN')
    if verdict.get('response'):tree='response mode (no repository)' 
    lines = ['NOT DONE: ' + first,
             'Full Blast Radius Check: ' + '; '.join(examined) + '. Outstanding: ' + first,
             enforcement,
             '', 'Result: ' + result_text,
             f'Task {verdict["task_id"]} · iteration {verdict["iteration"]} of 4 · HEAD {verdict["checked_head"]} · working tree {tree} · status SHA-256 {status_identity} · contract {verdict["contract_sha256"]} · stagecheck {verdict["manifest_sha256"]} · verdict {verdict_sha256}',
             '', 'CLEAR means only that no blocking defect was found by the checks that ran. Tooling results award no acceptance or product/runtime credit.']
    if quality:
        lines[5]+=' · quality policy '+str(quality['policy_sha256'])+' · record files '+json.dumps(quality['record_files'],sort_keys=True)
        lines += ['', 'Quality pending counts: '+json.dumps({name:c['pending_count'] for name,c in quality['checks'].items()},sort_keys=True),
                  'Blocking authority: '+json.dumps({'measurement':quality.get('blocking_by_measurement',[]),'override':quality.get('blocking_by_override',[])},sort_keys=True)]
    for title, mode in [('Blocking defects','blocking'),('Report-only findings','report_only')]:
        lines += ['', '## ' + title]
        selected = [d for d in verdict['defects'] if d['mode']==mode]
        if not selected:
            lines += ['None.']
        for d in selected:
            lines += ['', f'### {d["defect_id"]} · {d["check_id"]} · {d["status"]}',
                      '- Rule: ' + d['clause'],
                      f'- Where: {d["location"]["path"]}:{d["location"]["lines"]} · claim {d["claim_id"]}',
                      '- Classification: ' + ('self-check; not blocking' if mode=='report_only' else 'bound blocking check'),
                      '- Evidence label: ' + ('TEST_PROVEN (scope: the retained check execution)' if d['source'].startswith('checks/') else 'SOURCE_PROVEN (scope: the cited self-check output; no independent acceptance)')]
            for e in d['evidence']:
                if e['type']=='command':
                    lines += [f'- Found: command {json.dumps(e["argv"])}; exit {e["exit_status"]}; stdout {e["stdout_sha256"]}; stderr {e["stderr_sha256"]}; record {e["record"]} SHA-256 {e["record_sha256"]}']
                else:
                    fence='`'*max(3,1+max((len(x) for x in re.findall(r'`+',e['quote'])),default=0))
                    lines += [f'- Found: {e["path"]}:{e["lines"]} SHA-256 {e["sha256"]}', fence+'text',e['quote'],fence]
            lines += ['- Required outcome: ' + d['required_outcome']]
    lines += ['', f'Counts: {verdict["counts"]["blocking"]} blocking; {verdict["counts"]["report_only"]} report-only; {verdict["counts"]["not_run"]} not run.']
    if verdict['questions']:
        lines += ['', '## Owner questions', *['- ' + q for q in verdict['questions']]]
    lines += ['', '## For the generator',
              '1. Repair every blocking defect in the layer that owns it and sweep every same-pattern instance (contract §10.3).',
              '2. Do not weaken a guard, assertion, test or expected result to clear a defect.',
              '3. Do not edit anything under stagecheck/ or evidence/stagecheck/, and do not run stagecheck.',
              '4. If you judge a defect to be wrong, say so in your next report, cite its defect id and your evidence, and leave the work as it is. The owner decides.',
              '5. Update the claims file, rerun your self-audit, and for each defect id state closed with its proof or disputed with its evidence.', '']
    return '\n'.join(lines).encode()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--verdict',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    raw=Path(args.verdict).read_bytes()
    value=loads(raw)
    schema(value,load(Path(__file__).parent.parent/'schemas/verdict.schema.json'))
    with Path(args.output).open('xb') as f:
        f.write(render(value,digest(raw)))


if __name__=='__main__':
    main()
