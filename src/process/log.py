"""Daemon logging: a rotating file at /var/log/pretzel-ai/pretzel-ai.log, plus stdout.

The file is what operators follow with `tail -f`, mirroring the pretzel daemons' spdlog files;
stdout is also emitted so systemd/journald captures early failures before the file handler opens
(and so a foreground run still prints).
"""

import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = "/var/log/pretzel-ai"
LOG_FILE = os.path.join(LOG_DIR, "pretzel-ai.log")

_FMT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

# The one point where source wins over the unit file.
#
# The level normally comes from outside: --log-level on the command line, or
# PZ_PRETZEL_AI_LOG_LEVEL in the environment, both read in main.py. Changing either means editing
# a systemd unit and reloading it, which is a round trip nobody wants in the middle of chasing
# something - so this constant overrides both, and is the only thing that does.
#
# None hands the decision back to the unit. Any of LEVELS takes it away.
#
# Set deliberately and put back deliberately. A daemon left here on "debug" writes the text
# operators typed into a file on disk, which is why setup() says so out loud on every start
# rather than letting it pass quietly.
OVERRIDE_LEVEL = "debug"

LEVELS = ("debug", "info", "warning", "error")


def setup(level=logging.INFO):
    """The root logger, set once. `level` is what the caller asked for; OVERRIDE_LEVEL wins."""
    forced = ""
    if OVERRIDE_LEVEL:
        forced = OVERRIDE_LEVEL.lower()
        level = getattr(logging, forced.upper())

    root = logging.getLogger()
    root.setLevel(level)
    fmt = logging.Formatter(_FMT)

    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    root.addHandler(stream)

    # Best-effort: if the log dir is not writable (e.g. a foreground dev run without root), keep
    # going on stdout alone rather than failing to start.
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        fileh = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=10)
        fileh.setFormatter(fmt)
        root.addHandler(fileh)
    except OSError as e:
        root.warning("file logging disabled (%s): %s — logging to stdout only", LOG_FILE, e)

    # Said after the handlers exist, so it lands in the file as well as on stdout.
    if forced:
        root.warning("log level forced to %s in process/log.py (OVERRIDE_LEVEL) — the unit file "
                     "and --log-level were ignored", forced.upper())

    # Keyed on the level that is actually in effect, not on what was asked for: the override can
    # turn this on when nobody passed --log-level debug, and the warning has to follow the fact.
    if root.isEnabledFor(logging.DEBUG):
        root.warning("log level is DEBUG — request dumps include the text operators typed")
