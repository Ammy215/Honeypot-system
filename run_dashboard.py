#!/usr/bin/env python3
"""
Start the HoneyShield dashboard with its database pool already warming.

    python run_dashboard.py                        # instead of: streamlit run dashboard/app.py
    python run_dashboard.py --server.port 8502     # any `streamlit run` option passes through

`streamlit run dashboard/app.py` still works, and is nearly as fast after a
restart — most of that saving came from moving each page's heavy imports
below its auth gate, which helps both. What the launcher adds is timing: it
starts opening the database pool (5 TLS + SCRAM handshakes, ~3.6 s) the moment
the server process starts, instead of when the first browser reaches the
sign-in screen. Sign-in waits for that pool, so starting it early is the
difference between signing in straight away and waiting on handshakes.

Two designs were measured and rejected, and the reasons shape this file:

  - Preloading every heavy module BEFORE the server listened made the first
    sign-in form 1.7 s faster and opened the port 1.7 s later — a wash for
    anyone who opens the browser at once. Importing is CPU-bound; doing it
    earlier does not make it cheaper.
  - Preloading them in the BACKGROUND from process start was worse: the
    imports were still running when the first browser arrived, fought its
    request for the GIL, and made the first sign-in 3.5 s slower.

So only the network-bound half starts here. The CPU-bound half (pandas, the
data layer, plotly) is started by the sign-in screen itself, once its form
has been sent — see dashboard/login.py.

Must run in the SAME process as the server, which is why this calls
Streamlit's CLI in-process rather than spawning `streamlit run`: a warm pool
only helps the interpreter that holds it.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    # .env and .streamlit/config.toml are both resolved from the working
    # directory, so the launcher behaves the same wherever it is invoked from.
    os.chdir(ROOT)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    from dashboard import login      # the auth gate's own imports, ~80 ms

    login.start_warm_up(imports=False)
    print("HoneyShield dashboard — database pool warming in the background; starting the server…")

    from streamlit.web import cli

    sys.argv = ["streamlit", "run", str(ROOT / "dashboard" / "app.py"), *sys.argv[1:]]
    return cli.main()


if __name__ == "__main__":
    sys.exit(main())
