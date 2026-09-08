# 2026-09-07 — transport / guardrail 축 분리

짝 문서: `pretzel` 저장소 `.claude/session_memory/2026-09-07-ai-route-split.md`

## 수행

### 두 축 분리

| | 이전 | 이후 |
|---|---|---|
| 필드 | `guardrail` 1개 | `transport` + `guardrail` 2개 |
| 값 | `none` / `api_application` / `ai_gateway` | `direct`\|`ai_gateway` × `none`\|`api_application` |
| 조합 | 3행. 나머지는 표현 불가 | 4쌍. 서로 제약하지 않음 |
| 결정 지점 | `_build_route` 가 `guardrail` 하나를 읽어 쌍을 파생 | `_build_transport` / `_build_guardrail` 이 각자 한 필드씩. `_build_route` 는 짝만 지음 |

분리 사유 — 한 문자열이 라우팅과 검사자를 겸해서, 고객이 실제로 요구하는 두 배치를 말할 수 없었음:
게이트웨이를 라우팅으로만 쓰고 스캔은 어플라이언스가 하는 배치, 게이트웨이로 라우팅하고 아무도
검사하지 않는 배치. 부수적으로 `guardrail` 이라는 이름의 필드 값이 인프라 조각이라는 범주 오류.

`ai_gateway` 가드레일(위임 검사) 폐기. **이전 결정 번복** — 원래 채택 사유는 "게이트웨이가 시험
대상일 때 그 판정을 그대로 읽는 것이 정직한 답". 폐기 사유 2건:
- 프로필·디텍터·임계값이 전부 다른 콘솔에 있어 pretzel-ai 가 기술·설정·보고 불가
- tool_calls 를 보지 못함. 게이트웨이 훅이 completion 의 텍스트 `content` 로 스캔 요청을 만들고
  `tool_calls` 는 `content` 의 형제라 스캐너에 도달하지 않음(측정 2026-08-26). 그 표면이 agent
  서비스의 존재 이유

동반 제거 — `gateway_require_verdict`(proto 필드 7), `guardrail_builder.ai_gateway()`.
proto 는 필드 번호를 재사용하지 않고 폐기 주석만 남김.

| 파일 | 변경 |
|---|---|
| `grpc/pretzel_ai.proto` | `transport` = 11 신설. 필드 7 폐기. `Checkpoints` 주석에서 "게이트웨이가 좁힌다" 삭제 |
| `deployment/config.py` | `TRANSPORT_*` `TRANSPORTS` 신설. `GUARDRAIL_AI_GATEWAY` 제거. `GUARDRAIL_POINTS` 가 검사자만으로 키잉 |
| `deployment/config.py` | `uses_gateway()` 가 `transport` 를 읽음. 이전엔 `guardrail` 을 읽었고, 한 필드가 두 뜻이라 우연히 맞았을 뿐 |
| `deployment/engine.py` | `_build_transport` `_build_guardrail` 분리 |
| `deployment/guardrail.py` | `ai_gateway()` 삭제 |
| `grpc/handlers/config.py` | `_service()` 가 `transport` 전달, `gateway_require_verdict` 제거 |

`GUARDRAIL_POINTS` 를 검사자만으로 키잉하는 것이 직교성의 근거 — 스캔 요청을 턴에서 **여기서**
만들므로, 어느 transport 가 completion 을 나르든 네 지점 모두 도달 가능.

### 미인식 값 처리

`_read_route()` 는 UNFILTERED 로 씀. `config.py` 의 다른 모든 필드와 반대이고 의도적.

근거 — 가드레일 축의 그럴듯한 기본값이 `none` 이라, 반올림하면 **검사받도록 설정된 서비스가 검사
없이 턴을 서빙**함. 이 코드베이스가 막으려는 단 하나의 실패. 그래서 미인식 값이
`deployment/engine.py` 까지 살아 도착하고, 두 빌더가 이름째 거부하여 푸시 거부로 보고됨.

mgmtd 쪽도 같은 규칙(`AiConfig.cpp:serviceDoc` 이 기본값 없이 행 그대로 전달).

### 로그 정리

```
전  DEBUG [1/5] catalog (models=9, ...)
    DEBUG [2/5] transport (leg=direct, ...)
    DEBUG [3/5] guardrail (kind=none, ...)
    DEBUG [4/5] engine (class=ChatEngine, service=chat, ...)
    INFO  service chat ready: transport=... · guardrail=none          ← engine.py
    DEBUG [5/5] service (name=chat, state=ready, ...)                 ← service.py
    INFO  service chat: transport=... · guardrail=none                ← core.py 기동 시
    INFO  deployment applied: service chat: ...                       ← handlers/config.py

후  DEBUG catalog   (version=21, service=chat, models=9, ...)
    DEBUG transport (version=21, service=chat, kind=direct, ...)
    DEBUG guardrail (version=21, service=chat, kind=none, ...)
    DEBUG engine    (version=21, service=chat, class=ChatEngine, ...)
    INFO  service ready (version=21, service=chat, transport=... · guardrail=none)
```

- `[n/5]` 폐기 — 다섯 단계 중 하나도 돌지 않은 실패·스킵 케이스에도 번호가 붙어 있었음
- 모든 줄에 `version=` `service=` — `ApplyConfig` 가 gRPC 워커 풀(`MAX_WORKERS=8`)에서 돌아 푸시
  두 개가 겹치면 줄이 섞임. 빌드가 자기 DEBUG 4줄을 먼저 쓰는데 그 줄들이 서비스를 이름 대지
  않으면 독자가 귀속 불가
- 결과당 한 줄 — 서비스 상태를 말하는 곳은 `Services.build` 하나. 빌드 안 된 서비스까지 말할 수
  있는 유일한 지점이라는 것이 소유권 근거

## 처리한 결함

| 위치 | 원인 · 처리 |
|---|---|
| `deployment/engine.py` `build_chat_engine` | 성공 빌드마다 "service ready" 2줄(engine.py + service.py). engine.py 쪽 제거 |
| `grpc/handlers/config.py` `ApplyConfig` | 푸시마다 `deployment applied: service X` 를 서비스 수만큼 추가 출력. 버전 없음. `Services.build` 가 이미 버전 붙여 씀. 루프 삭제 |
| `grpc/server.py` | 위 루프만 쓰던 `describe_service()` 삭제 |
| `process/core.py` `_log_startup_state` | 기동 시 서비스 재나열. 수 ms 전 `Services.build` 가 쓴 줄의 얇은 사본. 삭제, 주소·버전만 남김 |
| `deployment/service.py` | 실패·스킵 케이스마다 INFO 문장 + DEBUG `[5/5]` 사본 2줄. 번호가 돌지 않은 5단계를 주장 |

## 검증

- **2026-09-08 09:24:52 재시작 → 09:24:55 캐시 복원 후 빌드.** 새 형식 실측:

```
INFO  pretzel-ai.deployment.config: restored the configuration pushed at version 21
DEBUG pretzel-ai.core: building services (version=21, services=[chat,agent])
DEBUG pretzel-ai.deployment.engine: catalog (version=21, service=chat, models=9, ...)
DEBUG pretzel-ai.deployment.transport: transport (version=21, service=chat, kind=direct, ...)
DEBUG pretzel-ai.deployment.engine: guardrail (version=21, service=chat, kind=none, ...)
DEBUG pretzel-ai.deployment.engine: engine (version=21, service=chat, class=ChatEngine, ...)
INFO  pretzel-ai.deployment.service: service ready (version=21, service=chat, transport=direct → anthropic, google, openai · guardrail=none)
INFO  pretzel-ai.deployment.service: service skipped (version=21, service=agent, reason=not in the pushed configuration)
INFO  pretzel-ai.core: listening on 127.0.0.1:50051
INFO  pretzel-ai.core: configuration: running-config version 21
```

- 09:24:57 / 09:25:11 / 09:25:12 3회 `ApplyConfig` 수신(mgmtd ready · fleet runtime start · 재연결).
  전부 서비스당 1줄. 중복 `deployment applied` 없음
- `services=[chat=direct/none(none)]` — mgmtd `describeService` 의 transport/guardrail 분리 표기가
  도달. 두 축이 wire 를 실제로 건넜다는 증거
- import: `.venv/bin/python3 -c "from src.process.core import Core"` OK
- `pretzel_ai_pb2_grpc.py` 의 손패치 import 생존 확인 — `from src.grpc import pretzel_ai_pb2`
- grep: `gateway_require_verdict` `GUARDRAIL_AI_GATEWAY` 코드 잔존 없음(proto 폐기 주석만 히트)

**미검증**
- `transport=ai_gateway`. 게이트웨이 키 미저장(`gateway_key=none`)이라 `transport_builder.ai_gateway`
  가 `TransportError` 로 거부되는 지점까지만 도달 가능
- `guardrail=api_application`. 빌더가 `GuardrailError` 고정
- 미인식 값 거부 경로. 본 세션 로그에 해당 푸시 없음. 콘솔이 두 축을 모두 쓰므로 정상 경로로는
  만들 수 없고, 별도 문서 주입 필요

## TODO

| 항목 | 왜 안 됐나 | 어디를 |
|---|---|---|
| `api_application` 가드레일 구축 | `src/guardrail/` 패키지 부재(09-02 재구조화에서 삭제). **인터페이스 불일치** — 구 구현은 `inspect_prompt`/`inspect_response`/`inspect_tool_call`/`inspect_tool_result` 4개, 새 엔진은 `inspect(checkpoint, turn, **content)` 1개 | 복원원 `git show 76606bc^:src/{guardrail.py,airs/client.py,airs/scan.py}`. 신설 `guardrail/{__init__,airs_client,airs,gate}.py` → `deployment/guardrail.py` 주석 해제 |
| AIRS 본문 한도 상수 | 구 `client.py` 의 `MAX_PROMPT_BYTES`=2MiB / `MAX_RESPONSE_BYTES`=2MiB / `MAX_CONTEXT_BYTES`=100MiB 가 실측과 불일치. 실제는 **본문 총량 ~2MiB 에서 413, 재시도 불가** — 필드별이 아니라 합계 상한 | 신설 `guardrail/airs_client.py` |
| verdict 와이어 | proto `ChatResponse` 에 판정 필드 없음. 가드레일을 세워도 콘솔이 판정을 못 봄 | `grpc/pretzel_ai.proto` + `grpc/handlers/chat.py` + 콘솔 |
| `Core._build_services` | 호출부가 `run()` 1곳인데 docstring 이 "Called again by the config service when ApplyConfig arrives" 라고 주장. `apply_config` 는 `Services.build` 를 직접 부름 | 삭제(권장) 후 양쪽 직접 호출 — `cfg` import 도 같이 빠짐. 또는 `apply_config` 에서 호출 |
| `completion/wire.py` 문서 | "encoded, and decoded back" 이 `build_body`/`parse_choice` 를 역함수로 읽히게 함. 실제는 **요청** 본문 생성 / **응답**의 `choices[0]` 추출이라 짝이 아님. 이름은 유지가 정확 | `completion/wire.py:1` `completion/__init__.py:4` |
| `.service.py.swp` | 2026-09-08 09:10자 vim 스왑 잔존 | `src/deployment/.service.py.swp` |
| agent 서비스 | 툴 제거로 엔진 삭제. LangGraph 도입 예정 | `deployment/engine.py:build_agent_engine` |
| 테스트 0개, CI 없음 | 미착수 | 신규 |
