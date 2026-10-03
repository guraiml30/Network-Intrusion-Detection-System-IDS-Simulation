"""One command to run the whole IDS project.

    python run_all.py              tests -> dataset -> ML model -> API + dashboard
    python run_all.py --skip-ml    skip model training
    python run_all.py --no-tests   skip unit tests
    python run_all.py --api-only | --ui-only

Dashboard: http://127.0.0.1:8511      API docs: http://127.0.0.1:8010/docs
Servers bind to 127.0.0.1 (this laptop only). Press Ctrl+C to stop.
"""
import argparse
import importlib.util
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
PY = sys.executable


def step(title, cmd):
    print(f"\n=== {title} ===", flush=True)
    return subprocess.run(cmd, cwd=ROOT, env=ENV).returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-ml", action="store_true")
    ap.add_argument("--no-tests", action="store_true")
    ap.add_argument("--api-only", action="store_true")
    ap.add_argument("--ui-only", action="store_true")
    ap.add_argument("--api-port", default="8010")
    ap.add_argument("--ui-port", default="8511")
    a = ap.parse_args()

    need = {"streamlit": "streamlit", "fastapi": "fastapi", "uvicorn": "uvicorn",
            "pandas": "pandas", "numpy": "numpy", "sklearn": "scikit-learn", "joblib": "joblib"}
    miss = [pip for mod, pip in need.items() if importlib.util.find_spec(mod) is None]
    if miss:
        sys.exit(f"Missing packages: {', '.join(miss)}\nRun: pip install -r requirements.txt")

    if not a.no_tests and not step("Unit tests", [PY, "-m", "unittest", "discover", "-s", "tests"]):
        sys.exit("Tests failed. Fix them (or use --no-tests) before starting.")
    step("Generate synthetic dataset", [PY, "scripts/generate_dataset.py"])
    if not a.skip_ml:
        step("Train optional ML model", [PY, "-m", "netids.ml_model"])

    procs = []
    try:
        if not a.ui_only:
            print(f"\n>>> API docs:  http://127.0.0.1:{a.api_port}/docs", flush=True)
            procs.append(subprocess.Popen([PY, "-m", "uvicorn", "api:app", "--host", "127.0.0.1",
                                           "--port", a.api_port], cwd=ROOT, env=ENV))
        if not a.api_only:
            print(f">>> Dashboard: http://127.0.0.1:{a.ui_port}", flush=True)
            procs.append(subprocess.Popen([PY, "-m", "streamlit", "run", "app.py", "--server.address",
                                           "127.0.0.1", "--server.port", a.ui_port, "--server.headless", "true",
                                           "--browser.gatherUsageStats", "false"], cwd=ROOT, env=ENV))
            time.sleep(4)
            webbrowser.open(f"http://127.0.0.1:{a.ui_port}")
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        print("A server exited; shutting down.")
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    main()
