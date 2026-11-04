"""Owner response-hook REQUEST §6/§7: unchanged delivery suite, synthetic roots only."""
import tempfile,subprocess
from run_evals import *

def main():
    p=argparse.ArgumentParser();p.add_argument('--smoke',action='store_true');a=p.parse_args()
    tool=Path(__file__).resolve().parents[1]
    programme=Path('/home/magnus/Desktop/Desk/WIP/1. Team/Dir/RWA/NewArc/3m')
    with tempfile.TemporaryDirectory(prefix='response-regression-') as scratch:
        run,data,root,ft=fixture(Path(scratch),tool,programme.parent.parent/'AGENTS.md',programme)
        for i in range(1,11):
            out=root/'evidence'/('sp1_t'+str(i).zfill(2))/'synthetic';out.mkdir(parents=True)
            raw=b'synthetic retention only\n';(out/'stdout').write_bytes(raw);(out/'stderr').write_bytes(b'')
            create(out/'execution.json',{'argv':['synthetic-read'],'cwd':str(root),'exit':0,'stdout_sha256':digest(raw),'stderr_sha256':digest(b'')})
        argv=[sys.executable,'-B',str(ft/'evals/run_evals.py'),'--tool-root',str(ft),'--programme-root',str(root),'--contract',run['contract'],'--output-dir',str(Path(scratch)/'evaluation')]
        if a.smoke:argv.append('--smoke')
        r=subprocess.run(argv,capture_output=True,timeout=480,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        print(r.stdout.decode());print(r.stderr.decode(),file=sys.stderr)
        result=Path(scratch)/'evaluation/results.json'
        if result.exists():print(json.dumps({'scope':'synthetic delivery regression','results':load(result)},sort_keys=True))
        return r.returncode
if __name__=='__main__':sys.exit(main())
