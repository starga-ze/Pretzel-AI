"""./pretzel-ai install — create the venv, install deps, generate stubs, prepare the log dir.

Idempotent: safe to re-run. Requires root (writes /var/log/pretzel-ai).
"""

import os
import shutil
import subprocess
import sys

from script.utils import (
    ROOT_DIR, VENV_DIR, VENV_PY, VENV_PIP, REQUIREMENTS, LOG_DIR, run_cmd,
)
import script.build as build


def _invoking_user():
    """The human who ran sudo, so a repo-owned venv is not left root-owned."""
    return os.environ.get("SUDO_USER") or ""


def _chown_to_user(path):
    user = _invoking_user()
    if not user:
        return
    subprocess.run(["chown", "-R", f"{user}:{user}", path])


def _ensure_venv():
    if os.path.isfile(VENV_PY):
        print("[*] venv already present, skipping creation.")
        return
    # python3-venv is not part of a stock install.
    run_cmd(["apt-get", "install", "-y", "python3-venv", "python3-dev"],
            msg="Installing python3-venv/python3-dev")
    run_cmd([sys.executable, "-m", "venv", VENV_DIR], msg="Creating virtualenv (.venv)")


def _ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)
    # The daemon runs as root, so root ownership is correct; 0755 lets an operator tail the log.
    os.chmod(LOG_DIR, 0o755)
    print(f"[*] Log directory ready: {LOG_DIR}")


def run():
    _ensure_venv()

    run_cmd([VENV_PIP, "install", "--upgrade", "pip", "wheel"], msg="Upgrading pip/wheel")
    run_cmd([VENV_PIP, "install", "-r", REQUIREMENTS], msg="Installing dependencies")

    # The venv was created under sudo; hand it back so `./pretzel-ai build` (unprivileged) can use it.
    _chown_to_user(VENV_DIR)

    build.run()
    _chown_to_user(os.path.join(ROOT_DIR, "src"))

    _ensure_log_dir()
    print("[*] pretzel-ai install complete. Start it with: sudo ./pretzel-ai start")


if __name__ == "__main__":
    sys.path.insert(0, ROOT_DIR)
    run()
