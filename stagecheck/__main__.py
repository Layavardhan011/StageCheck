"""StageCheck module entrypoint for 'python -m stagecheck'."""

import sys
from stagecheck.cli.main import main

if __name__ == "__main__":
    sys.exit(main())

