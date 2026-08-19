"""./pretzel-ai stop — stop and disable the daemon. Requires root."""

import os
import subprocess
import sys

from script.utils import ROOT_DIR, SERVICE_NAME


def run():
    subprocess.run(["systemctl", "stop", SERVICE_NAME])
    subprocess.run(["systemctl", "disable", SERVICE_NAME])
    # Belt and suspenders: a manually-launched instance is not managed by the unit.
    subprocess.run(["pkill", "-f", "src.grpc.server"])
    print(f"[*] {SERVICE_NAME} stopped and disabled.")


if __name__ == "__main__":
    sys.path.insert(0, ROOT_DIR)
    run()
