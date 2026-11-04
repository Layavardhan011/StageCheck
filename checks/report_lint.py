import sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from common import *


def check(ctx, value):
    data = claims(ctx)
    report = ctx.read(ctx.run['report']).decode()
    lines = report.splitlines()
    def bad(cid, claim=''):
        value['defects'].append(ctx.defect(cid, 'checks/report_lint.py', ctx.run['report'], claim))
    nonempty = [x for x in lines if x.strip()]
    headers = ['NOT DONE:', 'Full Blast Radius Check:', 'Enforcement Self-Check:']
    if ctx.run.get('response'):
        from response_tokens import header_lines
        nonempty = header_lines(report,True)
    if len(nonempty) < len(headers) or any(not line.startswith(header) for line, header in zip(nonempty, headers)):
        bad('report.headers')
    table_groups = {int(m[1]) for line in lines if (m := re.match(r'^\s*\|\s*(\d{1,2})\s*\|', line)) and 1 <= int(m[1]) <= 11}
    if table_groups == set(range(1,12)):
        bad('report.table')
    counts = {k: 0 for k in ['checked','not_checked','not_applicable']}
    labels = ['SOURCE_PROVEN','TEST_PROVEN','RUNTIME_PROVEN','INDEPENDENTLY_REPRODUCED','INFERRED','UNKNOWN','NOT_APPLICABLE']
    vocabulary = loads(ctx.read(ctx.tool/'config/controlled_vocabulary.json'))
    terms = vocabulary['controlled'] + vocabulary['synonyms']
    wording = re.compile(r'\b(?:' + '|'.join(re.escape(x) for x in sorted(terms, key=lambda x: (-len(x), x))) + r')\b', re.I)
    for c in data['claims']:
        embedded = re.findall(r'\b(?:' + '|'.join(labels) + r')\b', c['text'])
        if embedded and embedded != [c['label']]:
            bad('report.label', c['id'])
        if c['text'] not in report:
            bad('report.claim_missing', c['id'])
        if c['label'] == 'INFERRED' and (c['kind'] in ['decision','requirement','test_expectation'] or 'confidence' not in c):
            bad('report.inference', c['id'])
        if ctx.run.get('response') and c['label'] in ['TEST_PROVEN','RUNTIME_PROVEN'] and not any(e['type']=='command' for e in c['citations']):
            bad('report.label',c['id'])
        groups = c['blast_radius']
        for g in groups:
            counts[g['label']] += 1
        engineering = ctx.run['depth'] != 'docs'
        if engineering and (sorted(g['group'] for g in groups) != list(range(1,12)) or
                any(g['label'] == 'checked' and not g['items'] for g in groups)):
            bad('report.groups', c['id'])
        completion = c['kind'] == 'completion' or wording.search(c['text'])
        if completion and (not c['scope'] or not c['citations'] or
                           any(g['label'] == 'not_checked' for g in groups) or
                           c['label'] in ['INFERRED','UNKNOWN']):
            bad('report.completion', c['id'])
    if 'counts' in data and data['counts'] != counts:
        bad('report.counts')
    if ctx.run.get('response'):
        from response_tokens import unbacked_tokens
        for token in unbacked_tokens(report,data,ctx.root,Path.home()):
            # Hash the token in its identity; locations stay exact and stable.
            value['defects'].append(ctx.defect('report.unbacked_token','checks/report_lint.py',ctx.run['report'],
                lines=[token['line'],token['line']],evidence_key=[token['kind'],token['value'],token['line'],token['start']]))


if __name__ == '__main__':
    sys.exit(main_check('report_lint', check))
