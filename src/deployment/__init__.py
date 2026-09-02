"""How this daemon is configured, and what it builds from that.

    config.py      the pushed document, as plain data. Read by everything here, builds nothing.
    service.py     the services, and the engines behind them. What Core holds.
    engine.py      one service's engine, and the only place the deployment matrix is read
    catalog.py     which models may be asked for
    transport.py   who serves the completion
    guardrail.py   who inspects the turn

The call order is service.py -> engine.py -> catalog.py + transport.py + guardrail.py.

Three builders, not two, because they answer three separate questions. One console field picks a
row of the matrix today, and engine.py is where that row is turned into a pair - but the leg and
the inspector are built apart, so giving a direct-path customer a guardrail is a different
argument at one call site rather than a different function.

Only chat is built, on the direct leg, with nothing inspecting. Everything else raises at build
time and is refused rather than quietly substituted: a service configured to be inspected must
not come up as one that is not, and a deployment that put a gateway in the path must not be
answered around it.
"""
