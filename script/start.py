"""./pretzel-ai start — run the inference daemon under systemd as a supervised infinite loop.

The gRPC server's wait_for_termination() is the loop; systemd (Restart=always) keeps it up. The
daemon logs to /var/log/pretzel-ai/pretzel-ai.log (see src.log), so operators follow it with
`tail -f /var/log/pretzel-ai/pretzel-ai.log`. Requires root.
"""

import os
import subprocess
import sys

from script.utils import (
    ROOT_DIR, VENV_PY, PKG_DIR, LOG_DIR, LOG_FILE, SERVICE_NAME, SERVICE_PATH, LISTEN, run_cmd,
)

UNIT_TEMPLATE = """\
[Unit]
Description=Pretzel AI inference service (gRPC)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={root}
ExecStart={python} -m src.server --listen {listen}
Restart=always
RestartSec=3
# The app writes {log_file} itself; journald keeps a copy of stdout/stderr for early failures.
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


def _stop_stray_server():
    """A manually-launched `python -m src.server` would hold the port from the unit."""
    subprocess.run(["pkill", "-f", "src.server"])


def run():
    if not os.path.isfile(VENV_PY):
        sys.exit(f"[ERROR] venv not found at {VENV_PY}. Run './pretzel-ai install' first.")

    # The daemon imports the generated stubs; a prior `clean` removes them, which would leave the
    # unit crash-looping on ImportError. Regenerate if they are missing before we (re)start.
    if not os.path.isfile(os.path.join(PKG_DIR, "inference_pb2.py")):
        import script.build as build
        build.run()

    os.makedirs(LOG_DIR, exist_ok=True)

    unit = UNIT_TEMPLATE.format(root=ROOT_DIR, python=VENV_PY, listen=LISTEN, log_file=LOG_FILE)
    with open(SERVICE_PATH, "w") as f:
        f.write(unit)
    print(f"[*] Wrote {SERVICE_PATH}")

    _stop_stray_server()

    run_cmd(["systemctl", "daemon-reload"], msg="systemctl daemon-reload")
    run_cmd(["systemctl", "enable", "--now", SERVICE_NAME],
            msg=f"Enabling and starting {SERVICE_NAME}")

    print(f"[*] pretzel-ai is running on {LISTEN}.")
    print(f"[*] Logs: tail -f {LOG_FILE}")


if __name__ == "__main__":
    sys.path.insert(0, ROOT_DIR)
    run()
