"""Owner accuracy prompt Part C/§7: append outcomes; actor identity is declarative."""
from quality import *

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',required=True);p.add_argument('--record');p.add_argument('--recover-owner',action='store_true');a=p.parse_args()
    if bool(a.record)==a.recover_owner:p.error('choose a record or explicit owner recovery')
    ctx=Context(load(canonical(a.run)))
    request={'actor':'owner'} if a.recover_owner else loads(ctx.read(canonical(a.record)))
    print(append_record(ctx,request,a.recover_owner))

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('NOT DONE: quality writer refused: '+str(exc),file=sys.stderr);sys.exit(3)
