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


def setup(level=logging.INFO):
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
