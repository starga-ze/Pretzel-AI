"""Shared paths and helpers for the pretzel-ai CLI scripts."""

import os
import subprocess
import sys

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))

VENV_DIR = os.path.join(ROOT_DIR, ".venv")
VENV_PY = os.path.join(VENV_DIR, "bin", "python")
VENV_PIP = os.path.join(VENV_DIR, "bin", "pip")
REQUIREMENTS = os.path.join(ROOT_DIR, "requirements.txt")

# The gRPC edge: the contract and its generated stubs live together, mirroring mgmtd/grpc/.
GRPC_DIR = os.path.join(ROOT_DIR, "src", "grpc")
PROTO_FILE = os.path.join(GRPC_DIR, "pretzel_ai.proto")
PROTO_DIR = GRPC_DIR
PKG_DIR = os.path.join(ROOT_DIR, "src")

# One daemon today; the log path is per-daemon so `tail -f /var/log/pretzel-ai/<daemon>.log`
# generalises if pretzel-ai ever grows a second process.
DAEMON = "pretzel-ai"
LOG_DIR = "/var/log/pretzel-ai"
LOG_FILE = os.path.join(LOG_DIR, f"{DAEMON}.log")

SERVICE_NAME = "pretzel-ai.service"
SERVICE_PATH = os.path.join("/etc/systemd/system", SERVICE_NAME)

# Keys, out of the repo. The unit reads this as an EnvironmentFile, and it is what makes the
# service runnable on its own — for a developer, or a benchmark run with no appliance in front of
# it. In a deployment the keys come from the appliance's sealed store over ApplyConfig, and a
# pushed key wins over anything here.
#
# The same directory holds deployment.json, the 0600 cache of the last pushed document. Both are
# root-owned and neither is in the repo.
ENV_DIR = "/etc/pretzel-ai"
ENV_FILE = os.path.join(ENV_DIR, "keys.env")
STATE_FILE = os.path.join(ENV_DIR, "deployment.json")

# Where mgmtd's gRPC client dials (must match PZ_PRETZEL_AI_TARGET on the mgmtd side).
LISTEN = "127.0.0.1:50051"


def run_cmd(cmd, cwd=ROOT_DIR, msg=None, check=True):
    """Run a command, streaming its output; exit on failure when check is set."""
    if msg:
        print(f"[*] {msg}")
    result = subprocess.run(cmd, cwd=cwd)
    if check and result.returncode != 0:
        print(f"[ERROR] command failed ({result.returncode}): {' '.join(cmd)}")
        sys.exit(result.returncode)
    return result.returncode
