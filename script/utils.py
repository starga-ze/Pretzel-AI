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

CONFIG_FILE = os.path.join(ROOT_DIR, "config.json")

# One daemon today; the log path is per-daemon so `tail -f /var/log/pretzel-ai/<daemon>.log`
# generalises if pretzel-ai ever grows a second process.
DAEMON = "pretzel-ai"
LOG_DIR = "/var/log/pretzel-ai"
LOG_FILE = os.path.join(LOG_DIR, f"{DAEMON}.log")

SERVICE_NAME = "pretzel-ai.service"
SERVICE_PATH = os.path.join("/etc/systemd/system", SERVICE_NAME)

# Keys, out of the repo and out of the config document. The unit reads this as an EnvironmentFile
# and src/config.py already lets the environment win over the file for every one of them, so a key
# never has to be written into config.json — which is the direction the whole config is
# moving anyway (the declaration goes to the appliance's running-config, the secrets do not).
# Root-owned, 0600, created empty-but-commented by `start` and never overwritten after that.
ENV_DIR = "/etc/pretzel-ai"
ENV_FILE = os.path.join(ENV_DIR, "keys.env")

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
