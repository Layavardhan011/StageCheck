"""Owner accuracy prompt Part E/§7: deterministic figures from retained evidence.

Real outcomes are read only by an owner/Claude invocation. No self grading.
"""
from quality import *

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',required=True);a=p.parse_args()
    try:
        dest=write_measurement(Context(load(a.run)))
        print(json.dumps({'measurement':str(dest),'sha256':digest(dest.read_bytes())}));return 0
    except Exception as exc:
        print('NOT DONE: measurement refused: '+str(exc),file=sys.stderr);return 3

if __name__=='__main__':sys.exit(main())
