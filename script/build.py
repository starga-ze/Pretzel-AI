"""./pretzel-ai build — regenerate the gRPC stubs from src/grpc/pretzel_ai.proto.

Python needs no compile step, and this is not one. What it is is code generation: protoc turns the
proto into pretzel_ai_pb2*.py, and those are build artifacts with the staleness problem every build
artifact has — edit the contract, and the checked-out stubs describe the previous one until they
are regenerated.

So `build` exists for the same reason `./pretzel build` does, but nothing should depend on an
operator remembering to run it. `stale()` below is what install and start use to regenerate on
their own; the command is for regenerating without restarting the daemon.
"""

import os
import sys

from script.utils import ROOT_DIR, VENV_PY, GRPC_DIR, PROTO_DIR, PROTO_FILE, run_cmd


def stubs():
    """The generated files, in the order protoc writes them."""
    return [os.path.join(GRPC_DIR, name)
            for name in ("pretzel_ai_pb2.py", "pretzel_ai_pb2_grpc.py")]


def stale():
    """True when the stubs are missing or older than the proto they came from.

    Compared by mtime rather than by existence. Existence alone answers "has this ever been
    generated", which is the wrong question: the case that actually bites is a proto edited after
    the last generation, where the stubs are present, importable, and describe the previous
    contract. A daemon started on those comes up healthy and answers "method not found".
    """
    if not os.path.isfile(PROTO_FILE):
        return False
    proto_mtime = os.path.getmtime(PROTO_FILE)
    for stub in stubs():
        if not os.path.isfile(stub) or os.path.getmtime(stub) < proto_mtime:
            return True
    return False


def run():
    if not os.path.isfile(VENV_PY):
        sys.exit(f"[ERROR] venv not found at {VENV_PY}. Run './pretzel-ai install' first.")

    run_cmd(
        [VENV_PY, "-m", "grpc_tools.protoc",
         f"-I{PROTO_DIR}",
         f"--python_out={GRPC_DIR}",
         f"--grpc_python_out={GRPC_DIR}",
         PROTO_FILE],
        msg="Generating gRPC stubs from src/grpc/pretzel_ai.proto",
    )

    # The grpc plugin emits a flat `import pretzel_ai_pb2`, which resolves only when the stub's own
    # directory is on sys.path. Nothing puts it there: the daemon runs as `python -m src.grpc.server`
    # from the repo root, so sys.path carries the root and not src/grpc, and the generated stub
    # fails to import as shipped. Rewriting it to a package import makes it resolve from the root
    # like every other module here, with no sys.path manipulation to arrange or to remember.
    grpc_stub = os.path.join(GRPC_DIR, "pretzel_ai_pb2_grpc.py")
    with open(grpc_stub) as f:
        text = f.read()
    text = text.replace("\nimport pretzel_ai_pb2 as", "\nfrom src.grpc import pretzel_ai_pb2 as")
    with open(grpc_stub, "w") as f:
        f.write(text)

    print(f"[*] Generated: {GRPC_DIR}/pretzel_ai_pb2.py, pretzel_ai_pb2_grpc.py")


if __name__ == "__main__":
    sys.path.insert(0, ROOT_DIR)
    run()
