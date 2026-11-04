"""Owner response-hook REQUEST Part A/§7: mechanical fact-token backing.

This checks identities and byte references, never whether a quote supports a claim.
"""
import re,shlex
from pathlib import Path
from common import encode

LABELS=('SOURCE_PROVEN','TEST_PROVEN','RUNTIME_PROVEN','INDEPENDENTLY_REPRODUCED','INFERRED','UNKNOWN','NOT_APPLICABLE')
HEADERS=('NOT DONE:','Full Blast Radius Check:','Enforcement Self-Check:')

def header_lines(text,emphasis=False):
    lines=[line for line in text.splitlines() if line.strip()]
    return [line.strip().strip('*_').strip() if emphasis else line for line in lines[:3]]

def fact_tokens(text,root,home):
    """One detector: paths (quoted/Markdown/bare), hex, locators, URLs, labels, commands."""
    tokens=[]
    prefixes=[str(root).rstrip('/'),str(home).rstrip('/'),'/tmp']
    starts=r'(?:'+ '|'.join(re.escape(p) for p in sorted(set(prefixes),key=len,reverse=True))+r')(?=/|\b)'
    for line_no,line in enumerate(text.splitlines(),1):
        # Owner ruling: only this exact transport line is checked by the hook.
        if re.fullmatch(r'Claims: /[^\r\n]+',line):continue
        paths=[];occupied=[]
        # Delimited paths may contain spaces; bare paths stop at whitespace.
        for pattern in [r'`('+starts+r'[^`\n]*)`',r"['\"]("+starts+r"[^'\"\n]*)['\"]",r'<('+starts+r'[^>\n]*)>',r'\]\(('+starts+r'[^)\n]*)\)',r'('+starts+r'''[^\s`<>\[\]()'\"]*?)''' + r'''(?=$|[\s`<>\[\]()'\"])''']:
            for m in re.finditer(pattern,line):
                span=m.span(1)
                if any(a<=span[0]<b for a,b in occupied):continue
                value=m[1].rstrip('.,;:')
                if pattern.startswith('`') and re.search(r'\b(?:exit(?: status)?\s*[:=]?\s*-?\d+|result\b)',line,re.I):
                    # Command argument spaces are not part of a path. A root
                    # containing spaces is still a delimited file path; quote
                    # such executables inside the shell command itself.
                    if not (' ' in str(root) and value.startswith(str(root))):
                        try:
                            if len(shlex.split(value))>1:continue
                        except ValueError:pass
                paths.append({'kind':'path','value':value,'line':line_no,'start':span[0],'end':span[1]});occupied.append(span)
        tokens+=paths
        for kind,pattern in [
          ('hex',r'\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40})\b'),
          ('lines',r'\b(?:L|lines?\s+)(\d+)(?:\s*[–—-]\s*(?:L)?(\d+))?\b'),
          ('url',r'https?://[^\s`<>\]\)]+'),
          ('label',r'\b(?:'+ '|'.join(LABELS)+r')\b')]:
            for m in re.finditer(pattern,line):
                item={'kind':kind,'value':m[0].rstrip('.,;'),'line':line_no,'start':m.start(),'end':m.end()}
                if kind=='lines':item['lines']=[int(m[1]),int(m[2] or m[1])]
                tokens.append(item)
        if re.search(r'\b(?:exit(?: status)?\s*[:=]?\s*-?\d+|result\b)',line,re.I):
            for m in re.finditer(r'`([^`]+)`',line):
                value=m[1]
                if value not in LABELS and not re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|L\d+(?:[–—-]L?\d+)?',value):
                    tokens.append({'kind':'command','value':value,'line':line_no,'start':m.start(),'end':m.end()})
    return sorted(tokens,key=lambda t:(t['line'],t['start'],t['kind']))

def needs_claims(text,root,home):
    heads=header_lines(text,True)
    no_reads=len(heads)>=2 and heads[1].startswith(HEADERS[1]) and re.search(r'\bnothing (?:was )?read or run\b',heads[1],re.I)
    return not no_reads or bool(fact_tokens(text,root,home))

def unbacked_tokens(text,data,root,home):
    tokens=fact_tokens(text,root,home);citations=[e for c in data['claims'] for e in c['citations']]
    serialized=encode(data).decode();answer_lines=text.splitlines();bad=[]
    for token in tokens:
        kind,value=token['kind'],token['value'];backed=False
        if kind=='path':backed=any(e.get('path')==value for e in citations)
        elif kind=='hex':backed=value in serialized
        elif kind=='url':backed=any(value in encode(e).decode() for e in citations) or any(value in c['text'] for c in data['claims'])
        elif kind=='label':backed=any(c['label']==value and c['text'] in text for c in data['claims'])
        elif kind=='command':
            try:argv=shlex.split(value)
            except ValueError:argv=None
            backed=any(e.get('type')=='command' and e['argv']==argv for e in citations)
        elif kind=='lines':
            # Same-sentence file, else nearest preceding file; no global range guessing.
            line=answer_lines[token['line']-1]
            boundaries=[m.start() for m in re.finditer(r'[.!?](?:\s|$)',line)]
            left=max((b+1 for b in boundaries if b<token['start']),default=0)
            right=min((b for b in boundaries if b>=token['end']),default=len(line))
            same=[t for t in tokens if t['kind']=='path' and t['line']==token['line'] and left<=t['start']<right]
            prior=[t for t in tokens if t['kind']=='path' and (t['line'],t['start'])<(token['line'],token['start'])]
            path=(min(same,key=lambda t:abs(t['start']-token['start'])) if same else prior[-1] if prior else {}).get('value')
            a,b=token['lines']
            backed=a<=b and any(e.get('path')==path and 'lines' in e and e['lines'][0]<=a<=b<=e['lines'][1] for e in citations)
        if not backed:bad.append(token)
    return bad
