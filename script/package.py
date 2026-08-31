"""./pretzel-ai package — build the offline installer tarball for a production host.

    ./pretzel-ai package              # tmp/pretzel-ai-package-<stamp>.tar.gz
    ./pretzel-ai package --out /tmp   # write it somewhere else

A production host is assumed to have no repository, no compiler and no network. So the tarball
carries everything needed to run, and nothing that is only needed to build:

    src/          the app, with the gRPC stubs already generated (no protoc on the host)
    wheelhouse/   dependency wheels, so pip never has to reach PyPI
    sql/          schema migrations
    requirements.txt, config.example.json
    pretzel-ai-package  the installer (script/installer.py)

The wheels are downloaded **on this host**. Wheels carrying native extensions — psycopg_binary,
grpcio — are tied to glibc and the CPython ABI, so a package built here will not install on a
host with a different OS or Python. MANIFEST records both and the installer compares them before
touching anything: a half-installed host is the hardest state to recover from.
"""

import datetime
import hashlib
import json
import os
import shutil
import sys
import tarfile

from script.utils import ROOT_DIR, VENV_PIP, REQUIREMENTS, run_cmd

NAME = "pretzel-ai-package"

# What goes in. Anything not listed here never reaches production — dataset/, .venv/, .git/ and
# script/ are all build- or development-side assets.
PAYLOAD_DIRS = ("src", "sql")
PAYLOAD_FILES = ("requirements.txt", "config.example.json")

# Left out even from the directories above. Root-owned __pycache__ on a production host is a
# nuisance later, and bytecode is regenerated on first import anyway.
EXCLUDE_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache"}
EXCLUDE_SUFFIX = (".pyc", ".pyo", ".swp", ".bak")


def _skip(name):
    return name in EXCLUDE_NAMES or name.endswith(EXCLUDE_SUFFIX)


def _copy_tree(src, dst):
    shutil.copytree(src, dst, ignore=lambda d, names: [n for n in names if _skip(n)])


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _os_id():
    out = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    out[k] = v.strip('"')
    except OSError:
        return "?"
    return f"{out.get('ID','?')} {out.get('VERSION_ID','?')}"


def _stubs_present():
    """Without the stubs the host would need protoc, which it does not have. Stop here instead."""
    grpc_dir = os.path.join(ROOT_DIR, "src", "grpc")
    need = ("pretzel_ai_pb2.py", "pretzel_ai_pb2_grpc.py")
    missing = [n for n in need if not os.path.isfile(os.path.join(grpc_dir, n))]
    if missing:
        sys.exit(f"[Error] gRPC stubs are missing: {', '.join(missing)}\n"
                 f"        Run ./pretzel-ai build first.")


def _build_wheelhouse(stage):
    """Fetch the dependency wheels. On the host, pip sees only these (--no-index).

    pip, setuptools and wheel come along too, and not as a convenience. Debian and Ubuntu move
    ensurepip into the python3-venv package, so a stock host can have python3 and still be unable
    to make a venv that has pip in it. The installer therefore builds the venv with --without-pip
    and bootstraps pip from the wheel below, which needs that wheel to be here."""
    wh = os.path.join(stage, "wheelhouse")
    os.makedirs(wh, exist_ok=True)
    run_cmd([VENV_PIP, "download", "-r", REQUIREMENTS, "-d", wh],
            msg="Downloading dependency wheels (for this build host)")
    run_cmd([VENV_PIP, "download", "pip", "setuptools", "wheel", "-d", wh],
            msg="Downloading pip bootstrap wheels")
    n = len(os.listdir(wh))
    if n == 0:
        sys.exit("[Error] No wheels were downloaded. Check the network.")
    if not any(x.startswith("pip-") and x.endswith(".whl") for x in os.listdir(wh)):
        sys.exit("[Error] No pip wheel was downloaded; the installer could not bootstrap pip.")
    print(f"[*] Wheelhouse: {n} wheels")
    return n


def run():
    _stubs_present()

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    out_dir = os.path.join(ROOT_DIR, "tmp")
    for i, a in enumerate(sys.argv):
        if a == "--out" and i + 1 < len(sys.argv):
            out_dir = os.path.abspath(sys.argv[i + 1])
    os.makedirs(out_dir, exist_ok=True)

    stage_root = os.path.join(out_dir, f".stage-{NAME}")
    stage = os.path.join(stage_root, NAME)
    if os.path.isdir(stage_root):
        shutil.rmtree(stage_root)
    os.makedirs(stage)

    print(f"[*] Building {NAME} — {_os_id()} / Python {sys.version.split()[0]}")

    for d in PAYLOAD_DIRS:
        src = os.path.join(ROOT_DIR, d)
        if os.path.isdir(src):
            _copy_tree(src, os.path.join(stage, d))
            print(f"  added: {d}/")
    for f in PAYLOAD_FILES:
        src = os.path.join(ROOT_DIR, f)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(stage, f))
            print(f"  added: {f}")

    _build_wheelhouse(stage)

    installer = os.path.join(stage, NAME)
    shutil.copy2(os.path.join(ROOT_DIR, "script", "installer.py"), installer)
    os.chmod(installer, 0o755)

    # Checksums, so the installer can reject a tarball truncated in transit before it writes
    # anything.
    files = {}
    for root, dirs, names in os.walk(stage):
        dirs[:] = [d for d in dirs if not _skip(d)]
        for n in names:
            p = os.path.join(root, n)
            rel = os.path.relpath(p, stage)
            if rel == "MANIFEST.json":
                continue
            files[rel] = _sha256(p)

    mf = {
        "name": NAME,
        "version": ts,
        "built_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "built_on": _os_id(),
        "os": _os_id(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "arch": os.uname().machine,
        "files": files,
    }
    with open(os.path.join(stage, "MANIFEST.json"), "w") as f:
        json.dump(mf, f, ensure_ascii=False, indent=2)

    tar_path = os.path.join(out_dir, f"{NAME}-{ts}.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(stage, arcname=NAME)
    shutil.rmtree(stage_root)

    size = os.path.getsize(tar_path) / 1048576
    print()
    print(f"[*] Built: {tar_path}  ({size:.1f} MB, {len(files)} files)")
    print()
    print("    On the production host:")
    print(f"      scp {os.path.basename(tar_path)} prod:~/")
    print(f"      tar xzf {os.path.basename(tar_path)}")
    print(f"      cd {NAME} && sudo ./{NAME} install")


if __name__ == "__main__":
    sys.path.insert(0, ROOT_DIR)
    run()
