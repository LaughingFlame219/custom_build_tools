import subprocess, sys, os
here = os.path.dirname(os.path.abspath(__file__))
rc = 0
for t in ("test_apps.py", "test_e2e.py", "test_conf.py", "test_palo.py"):
    rc |= subprocess.call([sys.executable, os.path.join(here, "tests", t)])
sys.exit(rc)
