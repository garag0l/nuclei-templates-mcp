"""Run every template against the vulnerable and hardened mock servers and assert exact results.

Usage: python tests/run_templates.py [nuclei-binary]
Exit 1 on any missing or unexpected match.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOCK = ROOT / "tests" / "mock_mcp_server.py"
ALL = {p.stem for p in ROOT.glob("*/mcp/*.yaml")}

CASES = {
    "vulnerable": (["--port", "8801"], "http://127.0.0.1:8801",
                   {"mcp-unauthenticated-server", "mcp-tools-exposed", "mcp-cross-site-text-plain",
                    "mcp-dns-rebinding-host-not-validated", "mcp-sse-endpoint-unauthenticated"}),
    "stateless": (["--port", "8803", "--stateless", "--no-sse"], "http://127.0.0.1:8803",
                  {"mcp-unauthenticated-server", "mcp-tools-exposed", "mcp-cross-site-text-plain",
                   "mcp-dns-rebinding-host-not-validated"}),
    "hardened": (["--port", "8802", "--auth", "--validate-host", "--strict-content-type", "--no-sse"],
                 "http://127.0.0.1:8802", {"mcp-oauth-protected-resource"}),
}


def wait_up(url: str) -> None:
    for _ in range(40):
        try:
            urllib.request.urlopen(url + "/health", timeout=1)
        except urllib.error.HTTPError:
            return  # server answered (404 is fine)
        except OSError:
            time.sleep(0.25)
    raise SystemExit(f"mock at {url} did not start")


def main() -> int:
    nuclei = shutil.which(sys.argv[1] if len(sys.argv) > 1 else "nuclei")
    if not nuclei:
        raise SystemExit("nuclei not found")
    procs, failed = [], False
    try:
        for args, url, _ in CASES.values():
            procs.append(subprocess.Popen([sys.executable, str(MOCK), *args]))
            wait_up(url)
        for name, (_, url, expected) in CASES.items():
            out = subprocess.run(
                [nuclei, "-u", url, "-t", str(ROOT / "http"), "-jsonl", "-silent",
                 "-disable-update-check", "-no-interactsh", "-timeout", "10", "-retries", "0"],
                capture_output=True, text=True, check=False,
            )
            got = {json.loads(l)["template-id"] for l in out.stdout.splitlines() if l.strip().startswith("{")}
            missing, extra = expected - got, got - expected
            status = "ok" if not missing and not extra else "FAIL"
            print(f"[{status}] {name}: matched {sorted(got)}")
            if missing:
                print(f"    missing: {sorted(missing)}")
            if extra:
                print(f"    unexpected: {sorted(extra)}")
            if status == "FAIL":
                failed = True
                print(out.stderr[-3000:])
            for l in out.stdout.splitlines():
                if l.strip().startswith("{"):
                    r = json.loads(l)
                    if r.get("extracted-results"):
                        print(f"    {r['template-id']}: {r['extracted-results']}")
        untested = ALL - set().union(*(c[2] for c in CASES.values()))
        if untested:
            print(f"[FAIL] templates without a positive test: {sorted(untested)}")
            failed = True
    finally:
        for p in procs:
            p.terminate()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
