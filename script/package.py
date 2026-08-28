"""./pretzel-ai package — prod 호스트로 옮길 오프라인 설치 tar 를 만든다.

    ./pretzel-ai package              # tmp/pretzel-ai-package-<날짜>.tar.gz
    ./pretzel-ai package --out /tmp   # 다른 곳에 떨군다

prod 에는 저장소도, 컴파일러도, 인터넷도 없다고 가정한다. 그래서 tar 안에 들어가는 것은
'실행에 필요한 것 전부'이고, 빌드에만 쓰이는 것은 하나도 넣지 않는다:

    src/          이미 생성된 gRPC 스텁 포함 (prod 에 protoc 이 필요 없다)
    wheelhouse/   의존 라이브러리 휠 — pip 가 PyPI 를 보지 않아도 된다
    sql/          스키마 이행
    requirements.txt, config.example.json
    pretzel-ai-package  설치 스크립트 (script/installer.py)

휠은 **이 호스트에서** 받는다. psycopg_binary·grpcio 처럼 네이티브 확장을 담은 휠은 glibc 와
CPython ABI 에 묶여 있어서, 빌드 호스트와 prod 의 OS·파이썬이 다르면 그대로 쓰지 못한다.
그래서 MANIFEST 에 OS 와 파이썬 버전을 적어 두고 설치 시점에 대조한다 — 안 맞으면 설치를
시작하지 않고 멈춘다. 절반쯤 깔린 상태가 제일 고치기 어렵다.
"""

import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile

from script.utils import ROOT_DIR, VENV_PIP, REQUIREMENTS, run_cmd

NAME = "pretzel-ai-package"

# tar 에 담을 것. 여기 없는 것은 prod 에 가지 않는다 — dataset/, .venv/, .git/, script/ 는
# 전부 빌드·개발 자산이라 제외된다.
PAYLOAD_DIRS = ("src", "sql")
PAYLOAD_FILES = ("requirements.txt", "config.example.json")

# src/ 안에서도 빼는 것. __pycache__ 는 root 소유로 깔리면 나중에 성가시고, .proto 는
# 스텁이 이미 생성돼 있으므로 prod 에 필요 없다(참조용으로 남길 이유는 있어 그대로 둔다).
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
    """스텁이 없으면 prod 에서 protoc 을 돌려야 한다 — 그럴 수 없으므로 여기서 막는다."""
    grpc_dir = os.path.join(ROOT_DIR, "src", "grpc")
    need = ("pretzel_ai_pb2.py", "pretzel_ai_pb2_grpc.py")
    missing = [n for n in need if not os.path.isfile(os.path.join(grpc_dir, n))]
    if missing:
        sys.exit(f"[Error] gRPC 스텁이 없다: {', '.join(missing)}\n"
                 f"        먼저 ./pretzel-ai build 를 돌릴 것.")


def _build_wheelhouse(stage):
    """requirements.txt 를 휠로 받아 둔다. prod 의 pip 는 --no-index 로 이것만 본다."""
    wh = os.path.join(stage, "wheelhouse")
    os.makedirs(wh, exist_ok=True)
    run_cmd([VENV_PIP, "download", "-r", REQUIREMENTS, "-d", wh],
            msg="의존 라이브러리 휠 내려받는 중 (빌드 호스트 기준)")
    n = len(os.listdir(wh))
    if n == 0:
        sys.exit("[Error] 휠을 하나도 받지 못했다. 네트워크를 확인할 것.")
    print(f"[*] wheelhouse: {n}개 휠")
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

    print(f"[*] {NAME} 을(를) 만든다 — {_os_id()} / Python {sys.version.split()[0]}")

    for d in PAYLOAD_DIRS:
        src = os.path.join(ROOT_DIR, d)
        if os.path.isdir(src):
            _copy_tree(src, os.path.join(stage, d))
            print(f"  담음: {d}/")
    for f in PAYLOAD_FILES:
        src = os.path.join(ROOT_DIR, f)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(stage, f))
            print(f"  담음: {f}")

    _build_wheelhouse(stage)

    installer = os.path.join(stage, NAME)
    shutil.copy2(os.path.join(ROOT_DIR, "script", "installer.py"), installer)
    os.chmod(installer, 0o755)

    # 무결성 목록. scp 로 옮기다 잘린 tar 를 설치 전에 잡으려는 것이다.
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
    print(f"[*] 완성: {tar_path}  ({size:.1f} MB, {len(files)}개 파일)")
    print()
    print("    prod 에서:")
    print(f"      scp {os.path.basename(tar_path)} prod:~/")
    print(f"      tar xzf {os.path.basename(tar_path)}")
    print(f"      cd {NAME} && sudo ./{NAME} install")


if __name__ == "__main__":
    sys.path.insert(0, ROOT_DIR)
    run()
