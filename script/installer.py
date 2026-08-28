#!/usr/bin/env python3
"""pretzel-ai-package — prod 호스트에 설치한다.

    sudo ./pretzel-ai-package install [--prefix /opt/pretzel-ai]

이 파일은 패키지 안에서 단독으로 돈다. 저장소의 script/utils.py 를 import 하지 않는 이유가
그것이다 — prod 에는 저장소가 없고, 있어서도 안 된다. 여기서 쓰는 상수는 저장소 쪽과 값이
같아야 하므로, 바꿀 일이 생기면 script/utils.py 와 함께 고쳐야 한다.

설치가 하는 일:
  1. 사전 점검 (root / OS / python / 아키텍처 / 휠 존재)
  2. <prefix> 에 src·sql·config 배치
  3. venv 생성 후 wheelhouse 에서 오프라인 설치 (네트워크 불필요)
  4. /var/log/pretzel-ai, /etc/pretzel-ai/keys.env 준비
  5. systemd 유닛 작성 → enable → restart → 실제로 응답하는지 확인
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.abspath(os.path.dirname(__file__))

DEFAULT_PREFIX = "/opt/pretzel-ai"
SERVICE_NAME = "pretzel-ai.service"
SERVICE_PATH = os.path.join("/etc/systemd/system", SERVICE_NAME)
LOG_DIR = "/var/log/pretzel-ai"
LOG_FILE = os.path.join(LOG_DIR, "pretzel-ai.log")
ENV_DIR = "/etc/pretzel-ai"
ENV_FILE = os.path.join(ENV_DIR, "keys.env")
LISTEN = "127.0.0.1:50051"

# 저장소의 script/start.py 와 같은 모양이어야 한다. 다른 것은 WorkingDirectory 가 개발자
# 홈이 아니라 prefix 라는 점뿐이다.
UNIT_TEMPLATE = """\
# {path}
# pretzel-ai-package 가 생성했다. 손으로 고치면 다음 설치에서 덮어쓴다.
[Unit]
Description=Pretzel AI inference service (gRPC)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={prefix}
Environment="PZ_PRETZEL_AI_LOG_LEVEL={log_level}"
# 키는 저장소에도 config 문서에도 두지 않는다. 앞의 '-' 는 파일이 없어도 오류가 아니라는 뜻.
EnvironmentFile=-{env_file}
ExecStart={python} -m src.main --listen {listen}
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

ENV_TEMPLATE = """\
# pretzel-ai 키 — root 전용(0600). systemd 가 EnvironmentFile 로 읽는다.
#
# config.json 보다 환경변수가 우선한다(src/config.py). prod 의 config.json 은 키를 비워 두고
# 실제 값은 여기에 둔다 — config 가 유출돼도 키는 나가지 않는다.
PANW_AI_SEC_API_KEY=
PZ_PORTKEY_API_KEY=
"""


def say(msg):
    print(f"[*] {msg}")


def die(msg, hint=""):
    print(f"\n[Error] {msg}", file=sys.stderr)
    if hint:
        print(f"        {hint}", file=sys.stderr)
    sys.exit(1)


def run_cmd(cmd, msg=None, check=True):
    if msg:
        say(msg)
    r = subprocess.run(cmd)
    if check and r.returncode != 0:
        die(f"명령 실패: {' '.join(cmd)}")
    return r.returncode


def manifest():
    with open(os.path.join(HERE, "MANIFEST.json")) as f:
        return json.load(f)


# ── 사전 점검 ────────────────────────────────────────────────────────────────────────────────

def preflight(mf):
    """설치 전에 막을 수 있는 것은 전부 여기서 막는다.

    절반쯤 설치된 상태가 제일 고치기 어렵다 — 파일은 깔렸는데 서비스가 안 뜨면, 원인이 이번
    설치인지 원래 있던 것인지 구분되지 않는다."""
    if os.geteuid() != 0:
        die("root 권한이 필요하다.", "sudo ./pretzel-ai-package install")

    # OS: 바이너리 휠(psycopg_binary, grpcio 등)이 glibc 에 묶여 있다.
    built = mf.get("os", "")
    try:
        cur = {}
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    cur[k] = v.strip('"')
        here = f"{cur.get('ID','?')} {cur.get('VERSION_ID','?')}"
    except OSError:
        here = "?"
    if built and here != built:
        die(f"OS 불일치: 패키지는 '{built}' 에서 만들어졌고 이 호스트는 '{here}' 다.",
            "네이티브 휠이 glibc 버전에 묶여 있어 그대로 쓸 수 없다. 같은 OS 에서 다시 패키징할 것.")
    say(f"OS 확인: {here}")

    py = mf.get("python", "")
    cur_py = f"{sys.version_info.major}.{sys.version_info.minor}"
    if py and not py.startswith(cur_py):
        die(f"Python 불일치: 패키지는 {py}, 이 호스트는 {cur_py}.",
            f"휠 파일명이 cp{py.replace('.','')[:3]} 로 고정돼 있어 설치되지 않는다.")
    say(f"Python 확인: {sys.version.split()[0]}")

    wh = os.path.join(HERE, "wheelhouse")
    n = len([f for f in os.listdir(wh)]) if os.path.isdir(wh) else 0
    if n == 0:
        die("wheelhouse 가 비어 있다.", "패키지가 손상됐다. 다시 만들어 옮길 것.")
    say(f"wheelhouse: {n}개 휠")

    if shutil.which("python3") is None:
        die("python3 가 없다.", "apt install -y python3 python3-venv")


def verify_files(mf):
    """MANIFEST 의 sha256 과 대조한다. scp 중 잘린 tar 를 여기서 잡는다."""
    bad = []
    for rel, want in mf.get("files", {}).items():
        p = os.path.join(HERE, rel)
        if not os.path.isfile(p):
            bad.append(f"{rel} (없음)")
            continue
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != want:
            bad.append(f"{rel} (해시 불일치)")
    if bad:
        die("패키지 무결성 검사 실패:\n        " + "\n        ".join(bad[:10]),
            "전송이 잘렸을 수 있다. tar 를 다시 옮길 것.")
    say(f"무결성 확인: {len(mf.get('files', {}))}개 파일")


# ── 설치 ─────────────────────────────────────────────────────────────────────────────────────

def place_payload(prefix):
    os.makedirs(prefix, exist_ok=True)
    for name in ("src", "sql"):
        src, dst = os.path.join(HERE, name), os.path.join(prefix, name)
        if not os.path.isdir(src):
            continue
        # 삭제 후 복사한다. 갱신 설치에서 예전 판의 파일이 남으면, 지워진 모듈이 그대로
        # import 되어 "고쳤는데 안 고쳐지는" 상태가 된다.
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        say(f"배치: {dst}")

    ex = os.path.join(HERE, "config.example.json")
    cfg = os.path.join(prefix, "config.json")
    if os.path.isfile(ex):
        shutil.copy2(ex, os.path.join(prefix, "config.example.json"))
        # 이미 있는 config.json 은 절대 덮지 않는다 — 운영자가 손본 값이 들어 있다.
        if not os.path.isfile(cfg):
            shutil.copy2(ex, cfg)
            say(f"config.json 생성 (키는 비어 있음): {cfg}")
        else:
            say("config.json 이 이미 있어 그대로 둔다.")


def make_venv(prefix):
    venv = os.path.join(prefix, ".venv")
    py = os.path.join(venv, "bin", "python")
    if not os.path.isfile(py):
        run_cmd([sys.executable, "-m", "venv", venv], msg=f"venv 생성: {venv}")
    pip = os.path.join(venv, "bin", "pip")
    wh = os.path.join(HERE, "wheelhouse")
    # --no-index: PyPI 를 보지 않는다. prod 가 인터넷에 못 나가도 되고, 나갈 수 있더라도
    # 빌드 때 고정한 것과 다른 판이 끼어들지 않는다.
    run_cmd([pip, "install", "--quiet", "--no-index", "--find-links", wh, "--upgrade", "pip", "wheel"],
            msg="pip/wheel 갱신 (오프라인)", check=False)
    run_cmd([pip, "install", "--quiet", "--no-index", "--find-links", wh,
             "-r", os.path.join(HERE, "requirements.txt")],
            msg="의존 라이브러리 설치 (오프라인)")
    return py


def prepare_runtime_dirs():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.chmod(LOG_DIR, 0o755)
    say(f"로그 디렉터리: {LOG_DIR}")

    os.makedirs(ENV_DIR, exist_ok=True)
    os.chmod(ENV_DIR, 0o755)
    if not os.path.isfile(ENV_FILE):
        with open(ENV_FILE, "w") as f:
            f.write(ENV_TEMPLATE)
        os.chmod(ENV_FILE, 0o600)
        say(f"키 파일 생성: {ENV_FILE}  ← 여기에 키를 채워야 한다")
        return False
    # 있으면 손대지 않는다. 운영자가 넣은 키를 덮어쓰는 것이 이 스크립트가 할 수 있는
    # 최악의 일이다.
    say(f"키 파일이 이미 있어 그대로 둔다: {ENV_FILE}")
    return True


def write_unit(prefix, python, log_level):
    unit = UNIT_TEMPLATE.format(path=SERVICE_PATH, prefix=prefix, python=python,
                                listen=LISTEN, env_file=ENV_FILE, log_level=log_level)
    with open(SERVICE_PATH, "w") as f:
        f.write(unit)
    os.chmod(SERVICE_PATH, 0o644)
    say(f"systemd 유닛 작성: {SERVICE_PATH}")


def wait_until_serving(timeout_sec=20):
    """`systemctl restart` 는 프로세스를 띄우기만 하고 돌아온다. Restart=always 가 붙어 있어서
    ImportError 로 죽는 데몬도 systemctl 눈에는 '활성'으로 보인다 — 포트가 열렸는지까지 봐야
    설치가 성공했다고 말할 수 있다."""
    import socket
    host, port = LISTEN.split(":")
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        alive = subprocess.run(["systemctl", "is-active", "--quiet", SERVICE_NAME],
                               check=False).returncode == 0
        if alive:
            try:
                with socket.create_connection((host, int(port)), timeout=1):
                    return True
            except OSError:
                pass
        time.sleep(0.5)
    return False


def install(args):
    mf = manifest()
    say(f"pretzel-ai 패키지 {mf.get('version','?')} (빌드 {mf.get('built_at','?')})")
    preflight(mf)
    verify_files(mf)

    prefix = os.path.abspath(args.prefix)
    place_payload(prefix)
    python = make_venv(prefix)
    fresh_keys = not prepare_runtime_dirs()

    write_unit(prefix, python, args.log_level)
    run_cmd(["systemctl", "daemon-reload"], msg="systemctl daemon-reload")
    run_cmd(["systemctl", "enable", SERVICE_NAME], msg=f"{SERVICE_NAME} 활성화")
    run_cmd(["systemctl", "restart", SERVICE_NAME], msg=f"{SERVICE_NAME} 시작")

    if wait_until_serving():
        say(f"{LISTEN} 응답 확인 — 설치 완료")
    else:
        print()
        say("데몬이 포트를 열지 못했다. 최근 로그:")
        subprocess.run(["journalctl", "-u", SERVICE_NAME, "-n", "30", "--no-pager"], check=False)
        die("설치는 끝났으나 서비스가 뜨지 않았다.",
            "DB 접속이나 키 설정을 먼저 확인할 것. 위 로그에 원인이 있다.")

    print()
    say("남은 작업:")
    if fresh_keys:
        print(f"      1. {ENV_FILE} 에 키를 채운다 (PANW_AI_SEC_API_KEY 등)")
        print(f"      2. sudo systemctl restart {SERVICE_NAME}")
    print(f"      · DB 스키마: {prefix}/sql/*.sql 를 번호순으로 적용한다")
    print(f"      · 상태 확인: systemctl status {SERVICE_NAME}")
    print(f"      · 로그:      tail -f {LOG_FILE}")


def main():
    ap = argparse.ArgumentParser(prog="pretzel-ai-package")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("install", help="이 호스트에 설치한다")
    p.add_argument("--prefix", default=DEFAULT_PREFIX, help=f"설치 위치 (기본 {DEFAULT_PREFIX})")
    p.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    args = ap.parse_args()
    if args.cmd != "install":
        ap.print_help()
        sys.exit(1)
    install(args)


if __name__ == "__main__":
    main()
