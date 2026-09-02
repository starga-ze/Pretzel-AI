# 2026-09-02 — 턴 경로 재구조화

## 최종 구조

```
src/
  main.py                                    인자 파싱 → Core
  process/      log.py  core.py              프로세스 부트스트랩. ApplyConfig 축 아님
  deployment/   config  catalog  transport   설정 → 객체 조립
                guardrail  engine  service
  engine/       __init__  chat  console      턴 실행
  completion/   __init__  wire               모델 호출 어휘 + 코덱. I/O 없음
  transport/    direct  ai_gateway           소켓
  grpc/  benchmark/  crawler/
```

의존 방향: `process/` → `deployment/` → `engine/` → `completion/` `transport/`

`completion/` 과 `transport/` 의 경계는 소켓. 타임아웃·자격증명·재시도는 `transport/` 에만 존재.

## 수행

### 패키지 분할

| 이동 | 근거 |
|---|---|
| `log.py` `core.py` → `process/` | ApplyConfig 가 아니라 CLI·환경변수로 결정. `deployment/` 불변식 위반 |
| `config.py` `deployment.py` `factory.py` `llm/catalog.py` → `deployment/` | push된 문서 → 조립 축으로 통합 |
| `chat/engine.py` → `engine/` | 턴 실행을 자체 패키지로 |
| `llm/` 해체 → `completion/` + `transport/` | 어휘·코덱과 소켓의 변경 사유가 다름 |
| `deployment/transport.py` 신설 | `guardrail.py` 가 leg 까지 정하던 결합 해소 |

`llm` 명명 폐기 사유 — 내용이 두 종류(어휘·코덱 / HTTP)인데 "LLM 관련" 으로 묶은 이름이라 열기 전 내용 추정 불가.
`http/` 는 후보에서 제외. 최상위 `http/` 패키지가 stdlib `http` 를 가려 `urllib.request` 가 `http.client` import 에 실패하는 것을 실증.

### 서비스·엔진

- `ServiceType(str, enum.Enum)` 도입. 값이 proto 문자열과 동일하여 wire 경계 번역 불필요
- `Services.get_engine(service_type)` / `get_service(service_type)`. `current_engine` 폐기 — 서비스가 둘이 된 이상 "현재 엔진" 이 단수로 정해지지 않음
- `build_chat_engine` / `build_agent_engine` 분리
- `_build_route()` 가 `(transport, guardrail)` 반환. 배포 매트릭스 단일 지점
- `ServiceNotBuilt(EngineError)` 도입

`ServiceNotBuilt` 분리 사유 — agent 를 `EngineError` 로 거부하니 `Services.failures()` 에 잡혀 문서 전체가 거부되고 chat 까지 정지. "설정 오류"(push 거부)와 "이 빌드가 구현 안 함"(거부 안 함)은 다른 상태.

### 툴 제거

- `engine/agent.py` 삭제
- `ToolRuntime` `ToolSpec` `ToolInvocation` `Role.TOOL` `Message.tool_calls` `Message.tool_call_id` `Completion.tool_calls` `Completion.wants_tools` `max_iterations` `TurnResult.iterations` 제거
- 유지: `POINT_TOOL_CALL` `POINT_TOOL_RESULT` (proto `Checkpoints` 계약), `benchmark` 의 `tool_calls` 결과 컬럼(옛 런 조회)

사유 — 툴 런타임이 한 번도 연결된 적 없음. LangChain/LangGraph 도입 예정.
부수 효과로 `Message.as_wire()` 가 27줄 → 3줄. `Role.TOOL` 특례와 `content=None` 예외가 전부 툴 때문이었음.

### 체크포인트 통합

- `_check_prompt` `_check_response` → `Engine._inspect(checkpoint, turn, result, latency, **content)` 하나로
- `Checkpoint` enum: `prompt` `response` `tool_call` `tool_result`. 값이 `cfg.POINT_*` 및 proto 와 동일
- 가드레일 인터페이스 4개 메서드 → `inspect(checkpoint, turn, **content)` 1개
- `_read_inline` `_gateway_block_verdict` 를 `_accept` 에서 제거

`tool_input`/`tool_output` 대신 `tool_call`/`tool_result` 채택 — 전자는 verdict 의 direction 어휘, 후자가 proto `Checkpoints` 필드명. 체크포인트에 direction 이름을 쓰면 설정 경계에 번역 발생.

`_read_inline` 이관 사유 — 인라인 훅 판정을 읽는 것은 게이트웨이 가드레일의 구현 방식이지 엔진의 일이 아님. RESPONSE 체크포인트가 `completion` 전체를 전달하여 가드레일이 스스로 문서에서 읽음. 한 턴에서 두 곳이 판정을 꺼내면 설명되지 않는 정지 발생.

`_accept` 는 기록 전용. `status` `raw` 를 `ok` 검사보다 먼저 기록 — 실패한 턴의 벤더 문서가 조사 대상.

### transport / guardrail 축 분리

초기에 둘을 `Guardrail` 객체 하나로 병합했다가 되돌림.

| | 병합 시 | 분리 후 |
|---|---|---|
| 근거 | 콘솔 드롭다운 하나가 둘 다 결정 | 그것은 콘솔의 사실이지 어플라이언스의 사실이 아님 |
| 결과 | `Engine.transport` 가 `guardrail.transport` 를 읽는 property. 내부 검사자를 `inspector` 로 개명해야 했음 | 평범한 필드 둘. property 소멸 |
| 조합 추가 | 병합 함수를 뜯어야 함 | `_build_route` 에 `elif` 한 줄 |

`gateway + AIRS` 행이 이 분리로 다시 표현 가능해짐 — 게이트웨이 훅은 tool_calls 를 스캐너에 전달하지 않으므로 에이전트에 필요한 조합.

### 식별자

`tr_id` 제거, `transaction_id` 로 통합. 없을 때만 `new_transaction_id()` 로 발급.

근거 2건:
- **측정 2026-08-26** — 스캔 API 의 id 슬롯은 3개가 아니라 2개. `tr_id` 와 `session_id` 가 같은 필드이며 session_id 가 우선. 콘솔 턴은 항상 세션이 있으므로 `tr_id` 는 매 호출 폐기되고 있었음
- 같은 날 `tr_id` 를 턴당 1개로 수정한 시점에 `transaction_id` 와 굵기가 동일해짐. 필드 2개, 의미 1개

`tr_` 접두사 유지 — mgmtd 는 `txn_*`, 어플라이언스는 `tr_*`. 스캔 리포트에서 발급 주체 식별 가능.

부수 해소 — `benchmark/caller.py` 가 `tr_id` 를 발급하는데 `_open` 이 덮어써서, `_scan_prompt` 케이스와 `_full_turn` 케이스의 id 출처가 달랐음.

### 의존성

`pan-aisecurity==0.11.0` 을 `requirements.txt` 에 추가. 설치는 돼 있었으나 미선언.

**이전 결정 번복.** 원래 사유는 "aiohttp 래퍼가 21개 전이 의존성을 끌어옴". **측정 2026-09-02** 로 그 판단이 패키지의 잘못된 절반을 본 것으로 확인:

```
aisecurity.scan.asyncio   aiohttp
aisecurity.scan.inline    urllib3, 동기        ← gRPC 워커 스레드에 필요한 쪽
```

도입 목적은 transport 가 아니라 **스키마**. `tool_event.metadata` 중첩(평탄화 시 400), `tool_event.input`/`output` 이 JSON 문자열(객체 시 500) 등이 생성 모델에 이미 반영.

제약 — `Scanner.sync_scan` 은 `Content` 1개만 받아 `contents` 1요소 배열로 감쌈. AIRS 는 `contents` 의 마지막 요소를 판정하고 앞을 맥락으로 읽으므로, 이 래퍼로는 대화 맥락 전달 불가.

Portkey → AI Gateway 네이밍 변경. `portkey_ai` 패키지명, `Portkey` 클래스, `x-portkey-trace-id` 헤더, `GATEWAY_BASE_URL` 은 wire·의존성 사실이라 유지.

### 코드 전개

턴 경로 한정. `benchmark/` `crawler/` 의 자명한 값-선택 삼항은 제외 — 전개 시 가독성 하락.

| 전 | 후 |
|---|---|
| `lambda _model: "max_tokens"` | `_default_token_param()` |
| `lambda model: model.split("/", 1)[-1]` | `_strip_routing_slug()` |
| `if (stop := ...) is not None` | `stop = ...` / `if stop is not None` |
| `next((v.error for v in ...), "")` | 명시적 루프 + `break` |
| 중첩 삼항 `getattr(...) or (X if Y else "none")` | `_names()` |
| `any(getattr(...) for ...)` | `_any()` `_slowest()` |
| 컴프리헨션 필터 | 명시적 루프. `historyFor` 는 필터 2개의 사유가 달라 분리 |

### 로깅

- `process/log.py` 를 `main.py` 에 연결
- `OVERRIDE_LEVEL` 도입. 소스가 유닛 파일·CLI 보다 우선. 강제 시 WARNING 출력
- `_build_services` 5단계 debug 추가

```
[1/5] catalog (models=3, default=openai/gpt-5.6-sol, providers=[openai,google,anthropic])
[2/5] transport (leg=direct, endpoints=[anthropic,google,openai], timeout=45.0s)
[3/5] guardrail (kind=none, checkpoints=[], note=...)
[4/5] engine (class=ChatEngine, service=chat, system_prompt=set, max_tokens=4096, fail_open=False)
[5/5] service (name=chat, state=ready, guardrail=none, checkpoints=[])
```

파라미터 `(k=v, k=v)`, 리스트 `[...]`. mgmtd 로그 형식과 일치.
엔진이 [4] 인 이유 — catalog·transport·guardrail 을 인자로 받아 마지막에 생성.
`system_prompt` 는 `set`/`none` 만 기록. 운영자 텍스트.

로거 이름 중복 해소 — `pretzel-ai.transport` ×3, `pretzel-ai.engine` ×2. 조립하는 쪽과 조립되는 쪽이 같은 이름이라 구분 불가였음.

```
pretzel-ai.deployment.{config,engine,transport,guardrail,service}   빌더
pretzel-ai.{engine,engine.chat}                                    실물
pretzel-ai.transport.{direct,ai_gateway}                           실물
```

`dump_chat_request` — 테두리 제거, 제목 `mgmtd -> grpc -> ChatRequest`, history `content` 는 크기만, `message` 20바이트 제한(UTF-8 바이트 단위 절단, `errors="ignore"`).

## 처리한 결함

| 위치 | 원인 · 처리 |
|---|---|
| `grpc/handlers/chat.py` `Chat()` | `return` 이 `if engine is None` 블록 밖. 제너레이터가 청크 0개로 즉시 종료. mgmtd 는 `no result`, 정상 종료라 트레이스백 없음. **Gemini 응답 불가의 실제 원인.** 들여쓰기 복구 |
| `transport/direct.py` `_parse` | Gemini OpenAI 호환 엔드포인트는 에러를 1요소 JSON **배열**로 반환. `isinstance(doc, dict)` 검사에서 `__raw__` 로 추락하여 503 이 `BAD_RESPONSE`(파싱 실패)로 오분류. 로그의 작은따옴표(`[{'error': ...}]`)가 `str(list)` 라는 단서. 배열 언랩 추가 → `UPSTREAM_ERROR` + 벤더 메시지 |
| `deployment/config.py` `save_cached` | `tempfile.mkstemp` 이 `try` 밖. `/etc/pretzel-ai/` 비쓰기 시 예외가 `ApplyConfig` 까지 전파되어, 적용 완료된 설정을 실패로 보고. `try` 안으로 이동 + `temporary_path` 초기화 |
| `process/log.py` 미연결 | `main.py` 가 `logging.basicConfig()` 사용. StreamHandler 만 붙어 `/var/log/pretzel-ai/pretzel-ai.log` 가 13:47 이후 정지. journald 에만 기록되던 상태 |
| `deployment/engine.py` | agent 거부가 문서 전체를 거부시켜 chat 정지. `ServiceNotBuilt` 로 분리 |

## 검증

- 로컬 가짜 벤더 HTTP 서버 + **실제 gRPC 클라이언트**로 `ApplyConfig` → `ListModels` → `Chat` 전 경로. 재구조화 매 단계마다 재실행
- 벤더가 수신한 HTTP 확인: `Authorization: Bearer`, `stream=False`, `max_tokens` 반영, 슬러그 제거된 모델명, `[SYSTEM, history…, USER]` 순서
- 3사 라우팅: openai / google(`/v1beta/openai/...`) / anthropic 각각 엔드포인트·모델명·`token_param` 정상. 미등록 벤더(`cohere`)는 카탈로그 제외 후 `BAD_REQUEST`
- 4가지 guardrail 설정: `none` 정상 / `api_application` 거부 / `ai_gateway` 는 leg 통과 후 guardrail 에서 거부 / `bogus` 거부
- 가짜 가드레일로 체크포인트: 통과(2회 호출) / PROMPT 차단(RESPONSE 미호출) / RESPONSE 차단 / `NOT_INSPECTED` fail_closed / fail_open
- Gemini 503 응답을 그대로 재현하여 `UPSTREAM_ERROR` 분류 확인
- `Completion` 5경로 실측: 성공 / `UPSTREAM_ERROR` / `BAD_RESPONSE` / `BAD_ROUTE` / `UNREACHABLE`
- 로그 파일 복구를 임시 디렉터리에서 핸들러 부착 확인(`StreamHandler` + `RotatingFileHandler`)

**미검증** — 실제 벤더 3사 호출. 키가 없어 OpenAI 호환 엔드포인트가 실제로 `Bearer` 를 수용하는지 미확인. 특히 Anthropic 네이티브 API 는 `x-api-key` + `anthropic-version` 사용. `Endpoint` 에 `auth_header` `auth_prefix` `headers` 필드가 있으나 `deployment/transport.py:direct()` 가 채우지 않음

## TODO

| 항목 | 왜 안 됐나 | 어디를 |
|---|---|---|
| `pretzel-ai` 재시작 | 미배포. `Chat()` 들여쓰기 수정이 응답 불가를 해소 | `systemctl restart pretzel-ai` |
| `guardrail/` 복구 | 세션 중 삭제. `AirsGuardrail` `GatewayGuardrail` `CheckpointGate` 필요 | `deployment/guardrail.py` 의 주석 블록. 백업 `scratchpad/pretzel-ai-before-merge.tgz` |
| AIRS 클라이언트 SDK 재작성 | A(SDK 전면) / B(모델만 채택 후 생성 클라이언트 직접 호출) 미결정. `sync_scan` 이 다중 `contents` 불가 | 신규 `guardrail/airs.py` |
| agent 서비스 | 툴 제거로 엔진 삭제. LangGraph 도입 예정 | `deployment/engine.py:build_agent_engine` — 현재 `ServiceNotBuilt` |
| `gateway + AIRS` 조합 | 양쪽 빌더는 동작하나 조합 미작성 | `deployment/engine.py:_build_route` `elif` 1줄 |
| 벤더별 인증 헤더 | 3사 모두 `Bearer` 고정. Anthropic 401 가능성 | `deployment/transport.py:direct()` 가 `Endpoint.auth_header` 미설정 |
| `Completion.finish_reason` `model` | 아무도 안 읽음. `finish_reason == "length"` 는 답 잘림 신호인데 콘솔 미전달 | `engine/__init__.py:_accept` → `TurnResult` |
| mgmtd 가 agent `ServiceConfig` 미전송 | proto 는 `repeated` 지원, mgmtd 가 chat 만 push | mgmtd `AiConfig.cpp` |
| proto `tr_id` 주석 | "per iteration" 으로 실제와 불일치. 필드 자체는 이번에 제거됨 | `grpc/pretzel_ai.proto` `ChatRequest` |
| 테스트 0개, CI 없음 | 미착수 | 신규 |
