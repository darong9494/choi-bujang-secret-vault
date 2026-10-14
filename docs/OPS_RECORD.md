# 작전실 운영 기록 계약

`GET /api/ops`는 `aleph.ops.v1` 형식으로 운영 기록 연결 상태를 반환합니다. 학생 자기 점검이나 고정 가상 입력을 운영 결과로 승격하지 않습니다. 현재 운영 판정·탐지·회수·복구 기록을 읽는 연결이 없으므로 `source: not_connected`, `status: not_run`입니다.

| 항목 | 운영 미연결 때의 값 |
|---|---|
| `queriedAt` | 이번 상태 조회 시각 |
| `checkedAt` | 운영 기록 시각이 없으므로 `null` |
| `commit` | 배포 커밋. 운영 결과나 검증된 복구 버전을 뜻하지 않음 |
| `summary` | `total`, `blocked`, `failed`, `notRun`이 모두 `null` |
| 최상위 네 집계값 | `summary`와 동일한 `null` |
| `items` | 확인된 운영 기록이 없어 빈 배열 |
| `rules` | 실제 `RULE_IDS`의 개수·이름. 운영 성공 횟수가 아님 |
| `decision`, `detection`, `revocation`, `recovery` | 모두 `not_run`. 검증된 복구 버전은 `null` |

화면은 같은 응답의 `source`, `status`, `summary`, `items`를 검증합니다. 미연결이면 집계 칸에 미실행을 표시하고 숫자 0도 채우지 않습니다. 연결된 빈 기록의 0건과 아직 조회하지 못한 결과를 구분합니다. 숫자·행 불일치 또는 API 조회 실패 때는 이전 수치와 행을 비웁니다.

`src/operations.mjs`의 `operationsSnapshot(record)`는 서버 전용 어댑터 경계입니다. 현재 API는 `null`만 전달하며 브라우저·요청 본문·쿼리·가상 파일에서 운영 결과를 받지 않습니다. 실제 엔진 계약과 읽기 연결을 확인한 뒤에만 서버 전용 기록을 전달해야 합니다. 연결을 구현하거나 완료했다고 주장하지 않습니다.

서버 전용 기록을 전달할 때는 `source: operations`, 실제 ISO `checkedAt`, `summary`, `items`가 필요합니다. 각 행은 허용된 `attackId`, `category`(decision/detection/revocation/recovery), `stage`, `result`, 실제 `httpStatus`·`checkedAt`을 사용합니다. 미실행 행은 HTTP 상태·확인 시각이 없습니다. 서버는 행을 다시 세어 입력 합계와 대조하고 필요한 항목만 반환합니다. 본문·계정·기기 ID·토큰·임의 설명은 반환하지 않습니다. 이 어댑터 형식은 운영 엔진의 현재 외부 계약이라고 주장하지 않습니다.

학생 자기 점검은 별도입니다. `/api/checks`는 `aleph.student-checks.v1`, `source: student_self_check`로 자기 점검 결과를 반환합니다. `?case=<고정 사례>`는 `student_fixture` 가상 연습만 실행합니다. `src/ops-record.mjs`는 이 자기 점검과 제출용 수집기로 유지합니다. 이 결과는 작전실 운영 집계에 넣지 않습니다.

12단계의 `runAttackChecks`는 기존처럼 `attackId, stage, expected, observed, result`만 내보내며, 1~11단계의 세 필드 계약도 유지합니다. `npm run bundle`의 성공은 심판 통과나 41종 공격 방어 완료를 뜻하지 않습니다.
