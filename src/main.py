"""Entry point. Arguments and log level, then hand over to Core.

Nothing that serves a turn is imported here, so Core can be started from a test or a
foreground probe without going through argument parsing.
"""

import argparse
import logging
import os
import sys

from src.process import log as pa_log
from src.process.core import Core

LOG_LEVELS = ("debug", "info", "warning", "error")

DEFAULT_LISTEN = "127.0.0.1:50051"


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="pretzel-ai")

    parser.add_argument(
        "--listen",
        default=DEFAULT_LISTEN,
        help="host:port to bind",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("PZ_PRETZEL_AI_LOG_LEVEL", "info").lower(),
        choices=LOG_LEVELS,
        help="daemon log level",
    )
    return parser.parse_args(argv)


def setup_logging(level_name: str) -> None:
    """The root logger, set once. Delegated to process/log.py rather than done here.

    basicConfig() stood in for this and quietly cost the daemon its log FILE: it attaches a stream
    handler and nothing else, so everything went to stdout, journald caught it, and
    /var/log/pretzel-ai/pretzel-ai.log stopped growing the moment this process took over. An
    operator following that file with `tail -f` sees a service that has gone silent rather than one
    that is logging somewhere else.

    What is passed here is what the unit file or the command line asked for. It is not necessarily
    what runs: process/log.py has an OVERRIDE_LEVEL that wins, and says so when it does.
    """
    pa_log.setup(getattr(logging, level_name.upper()))


def main(argv=None) -> int:
    args = parse_args(argv)
    setup_logging(args.log_level)

    core = Core(listen_address=args.listen)
    return core.run()


if __name__ == "__main__":
    sys.exit(main())
