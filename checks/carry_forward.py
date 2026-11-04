import sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'bin'))
from common import *

# Addendum 14 §2 and audit aspect C1: every obligation a delivery or audit finds is listed under a
# CARRY_FORWARD heading with the row (or owner) that receives it. Applies to Markdown records only.
RECEIVER = re.compile(r'\b(SP[1-9]-[0-9][0-9A-Za-z-]*|T[0-9]{2}[0-9A-Za-z-]*|owner|none)\b', re.I)
HEADING = re.compile(r'^\s*(#+\s*)?(\d+\.\s*)?CARRY_FORWARD\b', re.I)
# Owner 2026-10-23 (carry.not_landed; Addendum 15 item 2): an entry that hands an obligation to a tracker row must quote
# text now present in that row, or say plainly that the row does not hold it and an owner tracker carry is requested.
ROW = re.compile(r'(?<![\w-])(SP[1-9]-[0-9][0-9A-Za-z]*)(?![\w-])')
QUOTE = re.compile(r'"([^"]{12,})"|\u201c([^\u201d]{12,})\u201d')
# Entries routed through the owner (proposals in audit records, owner-run tracker updates) are not claims that the row holds the text.
NOT_HELD = re.compile(r'not present|owner tracker carry|owner-run|\u2192\s*owner\b|->\s*owner\b|(^|[\s/|])owner\s*:', re.I)
TRACKER = 'RWA/start/DRWA_SP2_Task_Tracker.md'


def tracker_rows(ctx):
    path = ctx.root / TRACKER
    if not path.is_file():
        return None
    rows = {}
    for line in ctx.read(path).decode('utf-8', 'replace').splitlines():
        if line.startswith('| SP'):
            cells = [c.strip() for c in line.strip('|').split('|')]
            rows[cells[0]] = line
    return rows


def entries(lines):
    out = []
    for n, line in lines:
        s = line.strip()
        if s.startswith('|'):
            cells = [c.strip() for c in s.strip('|').split('|')]
            if all(re.fullmatch(r':?-{3,}:?', c) for c in cells if c) or (cells and cells[0].lower() in ('#', 'item', 'obligation', 'source')):
                continue
            out.append((n, s))
        elif re.match(r'^([-*]|\d+\.)\s+', s):
            out.append((n, s))
    return out


def check(ctx, value):
    if ctx.run.get('response'):
        value['not_run'].append('carry_forward: response mode has no delivery record')
        return
    data = claims(ctx)
    record = data.get('record')
    if not record or Path(record).suffix.lower() != '.md':
        value['not_run'].append('carry_forward: record is not a Markdown delivery or audit record')
        return
    text = ctx.read(Path(record)).decode('utf-8', 'replace').splitlines()
    start = next((i for i, l in enumerate(text) if HEADING.match(l)), None)
    if start is None:
        value['defects'].append(ctx.defect('carry.missing_section', 'checks/carry_forward.py', Path(record)))
        return
    section = []
    for i in range(start + 1, len(text)):
        if re.match(r'^\s*#+\s', text[i]):
            break
        section.append((i + 1, text[i]))
    found = entries(section)
    if not found and not RECEIVER.search(text[start] + ' ' + ' '.join(l for _, l in section)):
        value['defects'].append(ctx.defect('carry.unrouted', 'checks/carry_forward.py', Path(record), lines=[start + 1, start + 1]))
    for n, line in found:
        if not RECEIVER.search(line):
            value['defects'].append(ctx.defect('carry.unrouted', 'checks/carry_forward.py', Path(record), lines=[n, n], evidence_key=[n, line]))
    named = [(n, line, sorted(set(ROW.findall(line)))) for n, line in found]
    named = [x for x in named if x[2]]
    if not named:
        return
    rows = tracker_rows(ctx)
    if rows is None:
        value['not_run'].append('carry_forward: SP2 tracker not present; hand-off landing not checked')
        return
    # The record's own row (its Commit/evidence cell cites the record's folder) is the producer, not a receiver.
    folder = str(Path(record).parent).split('/3m/')[-1]
    own = {rid for rid, row in rows.items() if folder and folder in row}
    for n, line, ids in named:
        if NOT_HELD.search(line):
            continue
        ids = [rid for rid in ids if rid not in own]
        quotes = [a or b for a, b in QUOTE.findall(line)]
        for rid in ids:
            row = rows.get(rid)
            if row is None or not any(q in row for q in quotes):
                value['defects'].append(ctx.defect('carry.not_landed', 'checks/carry_forward.py', Path(record), lines=[n, n], evidence_key=[n, rid]))


if __name__ == '__main__':
    sys.exit(main_check('carry_forward', check))
