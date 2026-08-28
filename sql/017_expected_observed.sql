-- 기대값과 관측치를 이름으로 짝짓는다
--
-- 채점표는 두 축을 나란히 읽는 화면이다: 우리가 붙인 정답과 AIRS가 답한 것. 그런데 컬럼 이름이
-- `expected` / `verdict` / `expected_detectors` / `fired_detectors` 로 흩어져 있어서, 어느 쪽이
-- 기준이고 어느 쪽이 측정인지 이름만으로는 알 수 없었다. 같은 접두사로 짝지어 둔다.
--
--   expected_action   / observed_action     block | allow
--   expected_detector / observed_detector   블록.디텍터
--
-- `actual`이 아니라 `observed`인 이유: `actual`은 AIRS 출력이 사실이고 우리 라벨이 예측이라는
-- 뉘앙스를 준다. 실제 관계는 반대다 — 정답은 우리가 붙인 라벨이고, AIRS의 답은 그 정답에 대고
-- 재는 관측치다. 이름이 그 방향을 거꾸로 말하면 표를 읽을 때마다 되짚어야 한다.
--
-- run_case.verdict 는 특히 헷갈렸다. benchmark.row.verdict 는 malicious|benign(위협 여부)인데
-- run_case.verdict 는 block|allow(AIRS의 처분)였다. 같은 이름이 다른 것을 뜻하고 있었다.

BEGIN;

ALTER TABLE benchmark.row RENAME COLUMN expected            TO expected_action;
ALTER TABLE benchmark.row RENAME COLUMN expected_detectors  TO expected_detector;

ALTER TABLE benchmark.run_case RENAME COLUMN expected            TO expected_action;
ALTER TABLE benchmark.run_case RENAME COLUMN verdict             TO observed_action;
ALTER TABLE benchmark.run_case RENAME COLUMN expected_detectors  TO expected_detector;
ALTER TABLE benchmark.run_case RENAME COLUMN fired_detectors     TO observed_detector;

COMMIT;
