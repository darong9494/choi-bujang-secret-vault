# 작전실 서버 기록 계약

`GET /api/ops`와 `GET /api/checks`는 동일한 `aleph.ops.v1` 응답 형식을 사용합니다. `GET /api/checks?case=<고정 사례>`는 학생 코드의 가상 연습만 실행합니다. 임의 신원·사건·코드는 받지 않습니다.

| 항목 | 의미 |
|---|---|
| `checkedAt`, `commit` | 이번 수집 완료 시각과 배포 환경이 제공한 커밋. 커밋이 없으면 `null` |
| `summary` | `total`, `blocked`, `failed`, `notRun`. 같은 응답의 `items`만 집계 |
| 최상위 네 수치 | 요약 소비자를 위해 `summary`와 동일한 값 제공 |
| `items` | 공개 가능한 사례·기대·실제 응답·출처·요청 ID·확인 시각·결과 |
| `rules` | 현재 `RULE_IDS`의 개수와 이름 |
| `detection` | 가상 탐지 사례 ID와 운영 사건 전달의 미실행 상태 |
| `revocation` | 실제 회수 결과가 연결되지 않아 `not_run` |
| `recovery` | 검증 사본이 연결되지 않아 `available: false`, `verifiedVersion: null`. 배포 버전은 복구 버전으로 승격하지 않음 |

`items.kind`는 배포 API의 `live_api`, 고정 가상 연습 API의 `fixture_api`, 보내지 않은 `not_run`을 구분합니다. 요청을 보냈으나 응답을 확인하지 못하면 원래 요청 종류를 유지하고 `observed: network_error`, `result: not_run`으로 기록합니다. 보내지 않은 항목은 시각·HTTP 상태·요청 ID가 `null`이고 `observed: not_run`입니다.

`blocked`는 학생 자기 점검의 기대 응답이며 정상 요청의 허용도 포함합니다. 운영 심판의 통과나 41종 공격 방어 결과가 아닙니다. `failed`는 `result: breached`의 개수이고, 미실행·응답 미확인은 기대 응답에 포함하지 않습니다.

화면은 API 응답을 한 번 받아 상세 행으로 합계를 검증한 뒤 그 응답의 `summary`를 표시합니다. 합계·기록 형식이 다르거나 API가 실패하면 숫자와 상세 기록을 비웁니다. 합계나 사례 수를 화면 상수로 채우지 않습니다. API와 제출은 `src/ops-record.mjs`의 같은 수집기를 쓰지만 별도 실행 시 네트워크 상태가 다르면 결과도 달라질 수 있습니다. 각각의 시각과 출처를 대조해야 합니다.

12단계의 `runAttackChecks`는 `attackId, stage, expected, observed, result` 다섯 필드만 내보내고, 1~11단계의 기존 세 필드 계약은 유지합니다. 비교용 `observed`에는 HTTP 상태·본문 바이트 수·가상 API의 `jsonReady`만 넣습니다. 요청 ID는 작전실 기록의 별도 항목입니다. 메모 본문·토큰·기기 키는 응답이나 로그에 넣지 않습니다.
