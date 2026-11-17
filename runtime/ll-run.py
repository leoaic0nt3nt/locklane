#!/usr/bin/python3
"""Container-only launcher. The network firewall is the primary barrier."""
import json, os, signal, subprocess, sys, threading, time
from pathlib import Path

def ready():
    try:
        s=json.loads(Path('/state/status.json').read_text())
        return s.get('ready') is True and 0 <= time.time()-s['checked_at'] < 8
    except (OSError, ValueError, KeyError, TypeError):
        return False

if not ready():
    sys.exit('LOCKLANE: tunnel not verified; Claude was not started.')
child=subprocess.Popen(['claude',*sys.argv[1:]],start_new_session=True)
stop=threading.Event()
def watch():
    while not stop.wait(.5):
        if not ready():
            print('\nLOCKLANE: connection revoked; ending this session.',file=sys.stderr)
            try: os.killpg(child.pid,signal.SIGTERM)
            except ProcessLookupError: pass
            if not stop.wait(1):
                try: os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError: pass
            return
threading.Thread(target=watch,daemon=True).start()
try:
    code=child.wait()
except KeyboardInterrupt:
    os.killpg(child.pid,signal.SIGINT);code=child.wait()
finally:
    stop.set()
sys.exit(code)
