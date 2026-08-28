-- benchmark.row / run_case — 데이터셋 v2 스키마로 이행
--
-- v1은 `pretzel-ai → Portkey → LLM` 경로를 전제로 프롬프트 한 줄을 담았다. v2는 AIRS scan API를
-- 직접 호출하는 경로를 전제로, 행 하나가 곧 스캔 요청 1회다. 판정 대상이 프롬프트 문자열이 아니라
-- 요청의 `contents` 배열이므로, 그 배열을 저장할 칸이 필요하다.
--
--   scan_target      → checkpoint         prompt | response | response + context |
--                                          tool_event (input) | tool_event (input+output)
--   expected_labels  → expected_detectors `블록.디텍터` 표기 (prompt.injection 등)
--   prompt           → contents           AIRS 요청의 contents 배열 그대로 (JSONB)
--   severity, origin → 삭제               전자는 대분류마다 고정값, 후자는 전 행 동일
--
-- v1 세트는 이행하지 않고 버린다. 두 스키마는 측정 대상 자체가 달라서(프롬프트 한 줄 대 스캔 요청
-- 한 건) 한쪽을 다른 쪽으로 옮겨 적을 방법이 없고, 옮겨 적은 행으로 낸 점수는 어느 쪽 수치도
-- 아니게 된다. 지난 결과가 필요하면 v1 리포트를 보면 된다.

BEGIN;

-- 1. v1 세트와 그 실행 기록을 비운다. dataset이 CASCADE의 뿌리라 row도 함께 사라진다.
TRUNCATE TABLE benchmark.run_case, benchmark.run RESTART IDENTITY;
TRUNCATE TABLE benchmark.dataset RESTART IDENTITY CASCADE;

-- 2. benchmark.row 를 v2 모양으로.
ALTER TABLE benchmark.row DROP COLUMN IF EXISTS severity;
ALTER TABLE benchmark.row DROP COLUMN IF EXISTS origin;
ALTER TABLE benchmark.row DROP COLUMN IF EXISTS category_en;

ALTER TABLE benchmark.row RENAME COLUMN scan_target TO checkpoint;
ALTER TABLE benchmark.row RENAME COLUMN expected_labels TO expected_detectors;

-- prompt(TEXT) → contents(JSONB). 위에서 비웠으므로 옮길 데이터가 없다.
ALTER TABLE benchmark.row DROP COLUMN IF EXISTS prompt;
ALTER TABLE benchmark.row
    ADD COLUMN IF NOT EXISTS contents JSONB NOT NULL DEFAULT '[]'::jsonb;

-- contents는 반드시 원소가 있는 배열이어야 한다. 빈 배열은 스캔할 것이 없다는 뜻이고, 그런 행이
-- 세트에 섞이면 미탐으로 집계된다 — 데이터가 아니라 결함이므로 스키마에서 막는다.
ALTER TABLE benchmark.row DROP CONSTRAINT IF EXISTS row_contents_ck;
ALTER TABLE benchmark.row ADD CONSTRAINT row_contents_ck
    CHECK (jsonb_typeof(contents) = 'array' AND jsonb_array_length(contents) > 0);

-- 검사 시점으로도 거르므로 인덱스를 준다. v1의 scan_target 인덱스가 있었다면 이름만 바뀐 채로
-- 남아 있으니 지우고 다시 만든다.
DROP INDEX IF EXISTS benchmark.row_scan_target_idx;
CREATE INDEX IF NOT EXISTS row_checkpoint_idx ON benchmark.row (dataset_id, checkpoint);

-- 3. run_case — 케이스별 결과. 요청/응답 원문 칸은 그대로 두고 이름만 v2 어휘로.
ALTER TABLE benchmark.run_case RENAME COLUMN detectors TO fired_detectors;
ALTER TABLE benchmark.run_case
    ADD COLUMN IF NOT EXISTS expected_detectors TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS checkpoint         TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS threats            TEXT[] NOT NULL DEFAULT '{}';

-- `caught`(불리언)만으로는 '차단됐지만 기대 디텍터는 안 뜬' 경우를 표현할 수 없다. 스캔 1회가
-- 모든 디텍터를 돌리기 때문에 그 구분이 곧 실질 커버리지이고, v1에서 헤드라인 차단율이 실제
-- 성능을 가렸던 원인이 정확히 이 자리다. 다섯 갈래로 나눠 적는다.
ALTER TABLE benchmark.run_case
    ADD COLUMN IF NOT EXISTS outcome TEXT NOT NULL DEFAULT '';
ALTER TABLE benchmark.run_case DROP CONSTRAINT IF EXISTS run_case_outcome_ck;
ALTER TABLE benchmark.run_case ADD CONSTRAINT run_case_outcome_ck
    CHECK (outcome IN ('', 'hit', 'misclassified', 'miss', 'false_positive', 'clean_pass'));

CREATE INDEX IF NOT EXISTS run_case_outcome_idx ON benchmark.run_case (run_id, outcome);

COMMIT;
