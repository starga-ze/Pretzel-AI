"""./pretzel-ai stop — stop and disable the daemon. Requires root."""

import os
import subprocess
import sys

from script.utils import ROOT_DIR, SERVICE_NAME


def run():
    subprocess.run(["systemctl", "stop", SERVICE_NAME])
    subprocess.run(["systemctl", "disable", SERVICE_NAME])
    # Belt and suspenders: a manually-launched instance is not managed by the unit. Matches the
    # older module paths too, for an appliance upgraded across one of those moves.
    subprocess.run(["pkill", "-f", "--", r"-m src\.((grpc\.)?server|main)\b"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    print(f"[*] {SERVICE_NAME} stopped and disabled.")


if __name__ == "__main__":
    sys.path.insert(0, ROOT_DIR)
    run()
