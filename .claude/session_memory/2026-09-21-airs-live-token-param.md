# 2026-09-21 — AIRS 가동 · token_param 벤더 단위화

짝 문서: `pretzel` 저장소 `.claude/session_memory/2026-09-21-ai-model-catalog.md`

## 수행

### AIRS 가드레일 가동

`api_application` 가드레일이 처음으로 실제 트래픽에 붙음. 가동까지 3단계.

| 버전 | 시각 | 결과 |
|---|---|---|
| v36 | 09:39:47 | 거부 — `the AIRS guardrail is not built on this appliance yet` |
| v36 | 09:42:29 | 데몬 재시작 후 적용. 스캔 400 `AI Profile not found` |
| v37 | 09:43:59 | 프로파일명 오타 수정 후 정상 |

v36 거부 원인 — 데몬 기동 Sep 8 09:24:52, `deployment/guardrail.py` 작성 Sep 8 10:09.
45분 차이로 가드레일 구현 직전 스냅샷이 메모리에 올라가 있었음. 거부 문구가 현재 트리에 없는
문자열이라는 점이 단서.

프로파일명 오타 — `preztel-security-profile` → `pretzel-security-profile`.
응답의 `profile_id`(`8593ec9e-14f8-4d2b-a62b-2199d5d00a1d`)로 해석 성공 확인.

`airs_fail_open=false` 이므로 400 구간 동안 **모든 챗 턴이 prompt 체크포인트에서 정지**.
`code=NOT_INSPECTED`, reply 빈 문자열. 설계대로의 fail-closed.

### AIRS API 키 회전 결함 (측정 2026-09-21)

**증상** — 키 회전 push 가 `ok=True` 로 응답되고 콘솔에 새 키가 저장된 것으로 보이나,
스캔은 옛 키로 계속 나감. 로그·경고 없음.

**원인 3단계**

| 단계 | 사실 |
|---|---|
| 1 | `aisecurity/scan/inline/base.py` `ApiBase.create_api_client()` 이 `global_configuration.api_key` 를 읽어 `x-pan-token` 기본 헤더에 굽음. 키를 읽는 유일한 지점 |
| 2 | `ScanExecutor` 에 `@singleton`(`singleton_decorator`). 두 번째 `ScanExecutor()` 는 캐시 인스턴스를 반환하고 `__init__` 을 아예 실행하지 않음 → `create_api_client()` 재실행 없음 |
| 3 | `aisecurity.init()` 은 `global_configuration` 에 대입만 함. 그 전역을 다시 읽는 곳이 없음 |

`Scanner()` 를 새로 만들어도 무의미 — `Scanner` 는 클라이언트를 보유하지 않고 스캔 시
싱글톤 `ScanExecutor()` 를 호출.

**조치** — `guardrail/api_application.py` `_restamp_credentials()` 신설. 빌드마다 살아있는
클라이언트에 설정된 키를 직접 재기입.

```
client = ScanExecutor().api_client
client.set_default_header(HEADER_API_KEY, api_key)
client.configuration.host = endpoint
```

싱글톤 캐시를 깨지 않는 이유 — `singleton_decorator` 의 private 속성에 의존하게 됨.
`api_client` 프로퍼티와 `set_default_header` 는 둘 다 공개 API.
락 없음 — dict 한 칸 대입은 GIL 하에서 원자적.

측정 결과:

```
1회차 build(KEY-AAA) -> 전송 헤더: KEY-AAA
2회차 build(KEY-BBB) -> 전송 헤더: KEY-BBB   (로그 1회)
3회차 build(동일키)  -> 전송 헤더: KEY-BBB   (로그 없음)
```

`deployment/guardrail.py` TODO 3번을 "제한"에서 "이 파일에서 해결됨"으로 갱신.
남은 두 제한(contents 1개, per-request 타임아웃)은 그대로.

### token_param 벤더 단위화

**문제** — `running_config` 에서 OpenAI 61개 모델이 전부 동일한 `max_completion_tokens` 를
각자 보유. 한 벤더가 같은 답을 61번 반복.

**구조** — 우선순위 `모델 > provider > DEFAULT_TOKEN_PARAM`.

| 파일 | 변경 |
|---|---|
| `deployment/config.py` | `ProviderConfig.token_param` 신설 |
| `deployment/config.py` | `_provider_from()` 이 읽음 |
| `deployment/config.py` | `qualified_models()` 가 `model.token_param or provider.token_param` 으로 해석 |
| `deployment/config.py` | `to_document()` 가 빈 값을 쓰지 않음. 캐시도 슬림 형태 유지 |
| `grpc/pretzel_ai.proto` | `AiProvider.token_param = 6` |
| `grpc/handlers/config.py` | `_document()` 가 `p.token_param` 전달 |

**proto 필드 번호 6** — 4·5는 은퇴(`enabled`, `url`). 재사용 금지 규칙에 따라 6 사용.

**마이그레이션 불필요** — 옛 문서(모델마다 반복)가 동일하게 해석됨. 검증:

```
새 형태(provider + override)  openai/gpt-5 → max_completion_tokens, odd-one → weird
옛 형태(모델마다 반복)         동일 결과
아무것도 없음(google)          (empty → 카탈로그 기본값)
```

### 죽은 코드 제거

| 대상 | 상태 |
|---|---|
| `src/airs/`, `src/chat/` | 소스 0개, `__pycache__` 만 잔존. 76606bc(9/2)에서 원본 삭제됨. 참조 0건 |
| `/etc/pretzel-ai/keys.env` | 삭제 |
| `script/start.py` `ENV_TEMPLATE` `_ensure_env_file()` 유닛 `EnvironmentFile` | 삭제 (-52줄) |
| `script/installer.py` 동일 블록 | 삭제 (-38줄) |
| `script/utils.py` `ENV_FILE` | 삭제. `ENV_DIR` 은 `STATE_FILE` 이 사용하므로 유지 |

keys.env 가 죽어 있던 근거 — 템플릿이 제시하는 `PZ_OPENAI_API_KEY` `PANW_AI_SEC_API_KEY` 등
**전 변수가 `src/` 에서 참조 0건**. `src/` 가 환경변수에서 읽는 것은
`PZ_PRETZEL_AI_LOG_LEVEL` `PZ_PRETZEL_AI_STATE` `PZ_PG_PASSWORD` DSN 뿐.
`PANW_AI_SEC_API_KEY` 만 SDK 내부 `os.getenv` fallback 후보였으나,
`deployment/guardrail.py:65` 가 키 없으면 빌드를 거부하므로 도달 불가.

### 빌드 진입점 일원화

`process/core.py` `apply_config()` 가 `Services.build()` 를 직접 호출.
`_build_services()` docstring 은 "Called again by the config service when ApplyConfig arrives"
라고 주장했으나 실제 호출자는 기동 시점(`core.py:64`) 하나뿐.
결과 — `building services` DEBUG 라인이 push 경로에서 한 번도 출력되지 않음.

`apply_config()` 가 `self._build_services(config)` 를 타도록 변경. docstring 수정.

## 처리한 결함

| 위치 | 내용 |
|---|---|
| `guardrail/api_application.py` | AIRS 키 회전이 조용히 무시됨. SDK `ScanExecutor` 싱글톤 |
| `grpc/handlers/config.py` `_document()` | provider 단위 `token_param` 누락. proto·running_config 양쪽에 값이 있는데 도달하지 않음 |
| `grpc/pretzel_ai.proto` | `AiProvider` 에 `token_param` 필드 부재 → mgmtd `JsonStringToMessage(ignore_unknown_fields)` 가 조용히 폐기 |
| `process/core.py` | `_build_services()` docstring 이 사실과 불일치. push 경로 로그 누락 |
| `deployment/guardrail.py` | TODO 3번이 해결 후에도 "제한"으로 남아 있었음 |

## 검증

**실행 확인**

| 대상 | 결과 |
|---|---|
| benign 턴 | `ok=True` `verdict=allow` 양방향 스캔 2회(POST 200 × 2) |
| injection 턴 | `ok=False` `code=BLOCKED` `verdict=block` `categories: injection·agent hit`. prompt 에서 정지, 벤더 호출 없음 |
| `openai/gpt-6-astra` | `ok=True` |
| `google/gemini-3.8-flash` | `ok=True` |
| `anthropic/claude-opus-5` | `ok=False` — `Your credit balance is too low`. 계정 문제, 코드 아님 |
| `ListModels` | 113개 (openai 61 · google 41 · anthropic 11) |

**측정 사실 (2026-09-21)**

| 사실 | 근거 |
|---|---|
| `gpt-6-astra` 는 `max_tokens` 거부 | `Unsupported parameter: 'max_tokens' is not supported with this model.` |
| `gpt-3.5-turbo` 는 `max_completion_tokens` 수용 | 정상 응답. 세대별 규칙 분기 불필요 |
| 프로파일이 보고하는 카테고리 6종 | `agent` `dlp` `injection` `malicious_code` `toxic_content` `url_cats`. `db_security` 없음 — SDK 응답 모델 필드에서 파생 |
| 스캔 지연 | 150~450ms/회. benign 턴은 2회로 전체 약 2.1초 |
| Gemini TTS 모델은 텍스트 턴 불가 | `The requested combination of response modalities (TEXT) is not supported by the model.` |

**가정한 것** — `_restamp_credentials()` 를 실제 AIRS 키로 회전시켜보지는 않음.
가짜 키 2개로 헤더 변화만 확인.

**proto 재생성** — `script/build.py` 실행 후 `pretzel_ai_pb2_grpc.py` 의
손패치 import(`from src.grpc import pretzel_ai_pb2`)가 **보존됨**을 diff 로 확인.
파일 무변화.

## TODO

| 항목 | 이유 / 대상 파일 |
|---|---|
| `transport/ai_gateway.py` `GUARDRAIL_STATUS` 미정의 | 76606bc(9/2)부터 참조만 존재하고 정의 없음. `_to_completion()` 은 성공·실패 **모든** 경로에서 실행되므로 게이트웨이 턴 전체가 `NameError`. `gateway_api_key` 가 없어 빌드 단계에서 먼저 거부되는 덕에 아직 드러나지 않음. 가드레일 거부 상태 코드 숫자를 확정해야 상수를 넣을 수 있음 |
| `airs_timeout_sec` 미적용 | `Scanner.sync_scan` 이 타임아웃 인자를 받지 않음. 생성된 `ScansApi` 로 내려가야 해결. `deployment/guardrail.py` TODO 2번 |
| `contents` 1개 제한 | 동일 TODO 1번. 대화를 context 로 보낼 수 없음 |
| `chat_message` 저장 | `pretzel` 쪽 문서 참조. 9/2~9/21 대화 전부 미저장이었고 복구 불가 |
| 코드/워킹트리 미커밋 | `config.py` `handlers/config.py` `guardrail/api_application.py` `deployment/guardrail.py` `process/core.py` `script/*` proto + 재생성 스텁 |
