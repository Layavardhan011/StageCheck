"""Backward-compatibility re-export for checks/secret_findings.py.

Do NOT import 'secrets' directly from consumer code; import checks.secret_findings
to avoid colliding with Python standard library 'secrets'.
"""
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from secret_findings import check, findings

if __name__ == '__main__':
    from common import main_check
    sys.exit(main_check('secrets', check))
