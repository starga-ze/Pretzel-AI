"""The daemon's lifecycle.

One object owns the order things happen in:

    signals -> config -> services -> serve -> shutdown

Core does not know what a turn is. It builds the services that do, hands them to the
transport, and waits. Everything about a turn lives under deployment/.
"""

import logging
import signal
import threading
from concurrent import futures
from typing import Optional

import grpc

from src.deployment import config as cfg
from src.deployment.config import Config, ConfigRefused
from src.deployment.service import Services
from src.grpc import pretzel_ai_pb2_grpc
from src.grpc.server import PretzelAiServicer

log = logging.getLogger("pretzel-ai.core")

# How long a turn already running is given to finish when the daemon is asked to stop.
SHUTDOWN_GRACE_SEC = 10.0

# mgmtd calls one at a time per operator, but a benchtest run and a corpus refresh are both
# long streams that hold a worker for their whole duration. Eight leaves room for those plus
# the chat turns that must not queue behind them.
MAX_WORKERS = 8

# An upload carries a whole .jsonl in one message, past gRPC's 4 MB default. Without this the
# large-file case fails at the transport with a RESOURCE_EXHAUSTED that never reaches the
# store's own size check and its clearer message.
MAX_MESSAGE_BYTES = 33 * 1024 * 1024


class Core:
    def __init__(self, listen_address: str):
        self.listen_address = listen_address

        # Set once at startup, replaced when the appliance pushes a new one.
        self.config: Optional[Config] = None

        # The engines that serve turns. One per service.
        self.services: Optional[Services] = None

        # The gRPC server. Owned here for now; it moves to process.py when that exists.
        self.server = None

        # Raised by the signal handler, waited on by run().
        self._stop = threading.Event()

    # -- lifecycle ---------------------------------------------------------------------

    def run(self) -> int:
        """Bring the daemon up, wait, bring it down. Returns the process exit code."""
        self._install_signal_handlers()

        self.config = self._load_config()
        self.services = self._build_services(self.config)

        started = self._start_server()
        if not started:
            log.error("could not start the gRPC server")
            return 1

        self._log_startup_state()

        self._stop.wait()

        self._shutdown()
        return 0

    def _install_signal_handlers(self) -> None:
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)

    def _on_signal(self, signum, frame) -> None:
        log.info("signal %d received - stopping", signum)
        self._stop.set()

    # -- configuration -----------------------------------------------------------------

    def _load_config(self) -> Config:
        """The configuration this daemon starts on.

        The appliance is the source of truth and delivers it over ApplyConfig, so a fresh
        install has nothing yet. What is loaded here is the last pushed document, cached to
        disk so a restart does not leave the daemon mute until the next push.
        """
        config = Config.load_cached()

        if config.is_empty():
            log.info("no configuration cached - waiting for the appliance to push one")

        return config

    def _build_services(self, config: Config) -> Services:
        """One engine per service, built from the configuration.

        Called again by the config service when ApplyConfig arrives. Building before
        replacing is deliberate: a document that cannot produce working engines must leave
        the daemon running the ones that could.
        """
        log.debug("building services (version=%s, services=[%s])",
                  config.version or "none", ",".join(str(n) for n in cfg.SERVICES))
        return Services.build(config)

    def apply_config(self, config: Config) -> None:
        """Adopt a pushed configuration. Called by the config service, not by Core itself.

        Raises if the new configuration cannot produce engines. The caller reports the
        refusal to the appliance; the daemon keeps serving what it had.

        "Cannot produce engines" means a service the document NAMED did not build. A service
        the document leaves out is not a failure - the appliance decides which services
        exist. Built before anything is replaced, so a refusal costs nothing.
        """
        services = Services.build(config)

        failures = services.failures()
        if failures:
            reasons = []
            for service in failures:
                reasons.append(service.name + ": " + service.error)
            raise ConfigRefused("; ".join(reasons))

        self.services = services
        self.config = config
        config.save_cached()

        log.info("configuration applied (version %s)", config.version)

    # -- transport ---------------------------------------------------------------------

    def _start_server(self) -> bool:
        """Bind and start. Returns False if the port could not be taken.

        This is the part that moves to process.py: binding, starting, and the graceful stop
        below are one job, and it is not the same job as deciding what a turn is.
        """
        self.server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=MAX_WORKERS),
            options=[
                ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
                ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
            ],
        )

        # The servicer is handed Core, not an engine: ApplyConfig replaces the engines while
        # the daemon runs, and every handler reads through to whatever is current.
        servicer = PretzelAiServicer(self)
        pretzel_ai_pb2_grpc.add_PretzelAiServicer_to_server(servicer, self.server)

        # Loopback, no TLS - this is the mgmtd edge, not the vendor edge.
        bound_port = self.server.add_insecure_port(self.listen_address)
        if bound_port == 0:
            return False

        self.server.start()
        return True

    def _shutdown(self) -> None:
        """Stop taking new turns, let the running ones finish, then exit."""
        log.info("shutting down")

        if self.server is not None:
            self.server.stop(SHUTDOWN_GRACE_SEC).wait()

        log.info("stopped")

    # -- reporting ---------------------------------------------------------------------

    def _log_startup_state(self) -> None:
        """What this daemon is, on the lines an operator reads first."""
        log.info("listening on %s", self.listen_address)

        # The services are NOT listed again here. Services.build wrote one line for each of them,
        # with its reason and the version it was built from, a few milliseconds ago - and this
        # block used to print a second, thinner copy of the same thing under a different wording.
        #
        # What is left is the pair a reader wants at the point the daemon starts answering: the
        # address, and which configuration version it came up on.
        if self.config is None:
            version = 0
        else:
            version = self.config.version

        if version:
            log.info("configuration: running-config version %s", version)
        else:
            log.info("configuration: none pushed yet")
