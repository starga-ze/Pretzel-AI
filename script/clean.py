"""./pretzel-ai clean — remove generated stubs and Python caches."""

import glob
import os
import sys

from script.utils import ROOT_DIR, PKG_DIR


def _rm(path):
    """Remove a file or empty dir; return True on success, warn and skip on permission error."""
    try:
        if os.path.isdir(path):
            os.rmdir(path)
        else:
            os.remove(path)
        return True
    except FileNotFoundError:
        return False
    except OSError as e:
        # A leftover root-owned cache (from an earlier sudo run) should not fail the whole clean —
        # newer runs no longer create these, so this only bites once. See the CLI's dont_write_bytecode.
        print(f"[warn] skipped {path}: {e}")
        return False


def run():
    removed = 0

    for name in ("inference_pb2.py", "inference_pb2_grpc.py"):
        removed += _rm(os.path.join(PKG_DIR, name))

    for cache in glob.glob(os.path.join(ROOT_DIR, "**", "__pycache__"), recursive=True):
        if ".venv" in cache:
            continue
        for f in glob.glob(os.path.join(cache, "*")):
            _rm(f)
        removed += _rm(cache)

    print(f"[*] Cleaned {removed} item(s).")


if __name__ == "__main__":
    sys.path.insert(0, ROOT_DIR)
    run()
