"""./pretzel-ai start — deploy the unit and (re)start the daemon under systemd.

The gRPC server's wait_for_termination() is the loop; systemd (Restart=always) keeps it up. The
daemon logs to /var/log/pretzel-ai/pretzel-ai.log (see src.log), so operators follow it with
`tail -f /var/log/pretzel-ai/pretzel-ai.log`. Requires root.

Restart, not `enable --now`, for the same reason ./pretzel start restarts pretzel.target: --now
starts a unit that is stopped and does nothing at all to one that is already running. That made
`start` a no-op on the case it is actually run for — code changed, bring it up on the new code —
and the symptom was a daemon serving yesterday's build while the unit file on disk described
today's. `enable` still runs, but only for its other job: registering the unit for boot.
"""

import os
import socket
import subprocess
import sys
import time

from script.utils import (
    ROOT_DIR, VENV_PY, GRPC_DIR, LOG_DIR, LOG_FILE, SERVICE_NAME, SERVICE_PATH, LISTEN, run_cmd,
)

UNIT_TEMPLATE = """\
[Unit]
Description=Pretzel AI inference service (gRPC)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={root}
ExecStart={python} -m src.grpc.server --listen {listen}
Restart=always
RestartSec=3
# The app writes {log_file} itself; journald keeps a copy of stdout/stderr for early failures.
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


def _wait_until_serving(timeout_sec=15):
    """True once the daemon holds the listen port.

    `systemctl restart` returns as soon as the process is spawned, and Restart=always then respawns
    it forever — so a daemon that dies on an ImportError looks, to systemctl alone, exactly like one
    that started. Checking that something is actually listening is what tells those two apart, and
    it is the difference between `start` reporting success and `start` reporting the truth.
    """
    host, _, port = LISTEN.rpartition(":")
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        active = subprocess.run(["systemctl", "is-active", "--quiet", SERVICE_NAME],
                                check=False).returncode == 0
        if active:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.5)
                if probe.connect_ex((host or "127.0.0.1", int(port))) == 0:
                    return True
        time.sleep(0.5)
    return False


def _stop_stray_server():
    """Kill any server process not managed by the unit, whatever module path it was launched on.

    The pattern covers `src.server` as well as today's `src.grpc.server`: an appliance upgraded
    across that move can still be running the old path, and it holds the listen port exactly as a
    stray manual run would — a restart of the unit alone would then come up unable to bind.
    """
    # `--` before the pattern: it starts with "-m", which pkill would otherwise parse as an option
    # and answer with its usage text. Output is swallowed either way — pkill exits non-zero when
    # nothing matched, which is the normal case here and not something to report.
    # The regex is extended (…)? not BRE \(…\)?, which is what pkill -f matches with.
    subprocess.run(["pkill", "-f", "--", r"-m src\.(grpc\.)?server"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def run():
    if not os.path.isfile(VENV_PY):
        sys.exit(f"[ERROR] venv not found at {VENV_PY}. Run './pretzel-ai install' first.")

    # The daemon imports the generated stubs, so they have to be current before it comes up. Two
    # ways they are not: a prior `clean` removed them (the unit would crash-loop on ImportError),
    # or the proto was edited since they were generated — which is worse, because the daemon then
    # starts cleanly and serves the previous contract.
    import script.build as build
    if build.stale():
        build.run()

    os.makedirs(LOG_DIR, exist_ok=True)

    unit = UNIT_TEMPLATE.format(root=ROOT_DIR, python=VENV_PY, listen=LISTEN, log_file=LOG_FILE)
    with open(SERVICE_PATH, "w") as f:
        f.write(unit)
    print(f"[*] Wrote {SERVICE_PATH}")

    _stop_stray_server()

    run_cmd(["systemctl", "daemon-reload"], msg="systemctl daemon-reload")
    # Registration for boot only; starting is restart's job below.
    run_cmd(["systemctl", "enable", SERVICE_NAME], msg=f"Enabling {SERVICE_NAME}")
    run_cmd(["systemctl", "restart", SERVICE_NAME], msg=f"Restarting {SERVICE_NAME}")

    if not _wait_until_serving():
        subprocess.run(["systemctl", "status", SERVICE_NAME, "-n", "20", "--no-pager"],
                       check=False)
        sys.exit(f"[ERROR] {SERVICE_NAME} did not come up. See the status above and "
                 f"`journalctl -u {SERVICE_NAME}`.")

    subprocess.run(["systemctl", "status", SERVICE_NAME, "-n", "0", "--no-pager"], check=False)
    print(f"[*] pretzel-ai is running on {LISTEN}.")
    print(f"[*] Logs: tail -f {LOG_FILE}")


if __name__ == "__main__":
    sys.path.insert(0, ROOT_DIR)
    run()
