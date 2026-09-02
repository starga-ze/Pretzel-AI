"""The process itself: how it starts, what it logs, how long it lives.

    log.py    the root logger, set once at startup
    core.py   the lifecycle: signals -> config -> services -> serve -> shutdown

Nothing here is decided by the pushed configuration. What ApplyConfig governs lives under
deployment/; this is what runs before there is a configuration and what keeps running when
one is replaced.
"""
