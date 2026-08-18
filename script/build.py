"""./pretzel-ai build — regenerate the gRPC stubs from proto/inference.proto.

The Python analogue of compiling: there is nothing to link, but the generated
inference_pb2*.py must be rebuilt whenever the proto changes. Needs the venv (grpcio-tools),
so run `./pretzel-ai install` first on a fresh checkout.
"""

import os
import sys

from script.utils import ROOT_DIR, VENV_PY, PROTO_DIR, PROTO_FILE, PKG_DIR, run_cmd


def run():
    if not os.path.isfile(VENV_PY):
        sys.exit(f"[ERROR] venv not found at {VENV_PY}. Run './pretzel-ai install' first.")

    run_cmd(
        [VENV_PY, "-m", "grpc_tools.protoc",
         f"-I{PROTO_DIR}",
         f"--python_out={PKG_DIR}",
         f"--grpc_python_out={PKG_DIR}",
         PROTO_FILE],
        msg="Generating gRPC stubs from proto/inference.proto",
    )

    # The grpc plugin emits a flat `import inference_pb2`, which only resolves with the package
    # dir on sys.path. Rewrite it to a package-relative import so `from src import ...` works.
    grpc_stub = os.path.join(PKG_DIR, "inference_pb2_grpc.py")
    with open(grpc_stub) as f:
        text = f.read()
    text = text.replace("\nimport inference_pb2 as", "\nfrom src import inference_pb2 as")
    with open(grpc_stub, "w") as f:
        f.write(text)

    print(f"[*] Generated: {PKG_DIR}/inference_pb2.py, inference_pb2_grpc.py")


if __name__ == "__main__":
    sys.path.insert(0, ROOT_DIR)
    run()
