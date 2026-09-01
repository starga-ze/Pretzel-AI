"""pretzel-ai's entry point — the counterpart to mgmtd/main.cpp on the other side of the wire.

Everything that happens once, at start: read the command line, decide the log level, hand off to
src/core.py. Nothing about a chat turn is decided here, and nothing here is
imported by anything that serves one — which is the point of the file existing. `core.serve` is
importable on its own, so a test or a foreground probe can bring the service up without going
through argument parsing.

Run as `python -m src.main`; the systemd unit does exactly that (script/start.py).
"""

import argparse
import logging
import os

from src import log as pa_log
from src.core import serve

log = logging.getLogger("pretzel-ai")

LOG_LEVELS = ("debug", "info", "warning", "error")


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog="pretzel-ai",
                                 description="pretzel-ai gRPC inference service")
    ap.add_argument("--listen", default="127.0.0.1:50051",
                    help="host:port to bind (default: 127.0.0.1:50051)")
    # The request dump on Chat is DEBUG, and reaching it takes turning this up — which is the
    # point: that dump carries whatever a person typed. Named rather than a bare --debug flag so
    # the log itself records which level a run was at.
    ap.add_argument("--log-level",
                    default=os.environ.get("PZ_PRETZEL_AI_LOG_LEVEL", "info").lower(),
                    choices=LOG_LEVELS,
                    help="daemon log level (default: info)")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    pa_log.setup(getattr(logging, args.log_level.upper()))
    if args.log_level == "debug":
        log.warning("log level is DEBUG — request dumps include the text operators typed")

    serve(args.listen)


if __name__ == "__main__":
    main()
