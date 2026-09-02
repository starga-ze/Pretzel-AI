"""Who serves a completion. Two implementations of one job.

    direct.py       each vendor called at its own endpoint, with its own key
    ai_gateway.py   the AI Gateway routes it upstream

Apart from completion/ on one line: nothing in that package does I/O. It holds what a model call
IS - the vocabulary, and the encoding of it - and this package holds every socket. A reader
chasing a timeout, a credential or a retry looks here and nowhere else.

Which of the two a service runs is decided in deployment/engine.py and asked for by name in
deployment/transport.py. Neither file here reads `service.guardrail`, and neither knows one
exists: the leg and the inspector are separate axes, and a customer on the direct leg who is
given a guardrail must not become a customer whose traffic moved.

There is no shared Protocol. Both classes expose `complete(...)` and `describes`, and the engine
holds whichever it was handed - but an interface with two implementations that already agree
documents nothing that reading either class does not. It becomes worth naming when a third leg
arrives and the agreement stops being obvious.

Logger names mirror the module path - pretzel-ai.transport.direct and
pretzel-ai.transport.ai_gateway - and the builder next door is pretzel-ai.deployment.transport.
All three were called "pretzel-ai.transport" once, which meant a line could not say whether it
came from the thing being built or from the thing that built it.
"""
