-- benchmark.row — 알려진 한계를 남긴 행의 설명
--
-- 세트에는 통과가 확인된 기법이 일부러 한두 건씩 섞여 있다. 알려진 한계가 데이터에서 완전히
-- 사라지면 그 한계가 없다는 인상을 주고, 그렇다고 비율대로 섞으면 점수가 제품이 아니라 우리가
-- 얼마나 섞었는지를 재게 된다. 남기되 왜 남겼는지를 행에 붙여 두는 편이 양쪽을 피한다 —
-- 리포트 각주로 미루면 행과 설명이 따로 놀고, 다음 실행에서 누가 그 각주를 잃어버린다.
BEGIN;
ALTER TABLE benchmark.row ADD COLUMN IF NOT EXISTS note TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS row_note_idx ON benchmark.row (dataset_id) WHERE note <> '';
COMMIT;
