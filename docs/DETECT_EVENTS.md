# 9단계 탐지 연습 사건 계약

`npm run detect:test`는 학생이 작성한 `src/detect.mjs`의 `detect(events)`에 로컬 연습용 조회 사건을 전달합니다. 사건에는 가명 주체, 엔진 확인 형식의 단일 기기 ID, 요청 종류와 출처가 표시된 가상 신호가 포함됩니다.

```js
{ at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: { sub: 'learner_fixture' }, deviceId: 'bbbbbbbbbbbbbbbb', signals: { source: 'judge_fixture', network: 'usual', region: 'usual' } }
```

`GET` 사건은 `at`과 가명 `identity.sub`만 있어도 집계합니다. 같은 주체와 같은 유효한 `deviceId`(주어졌을 때)의 조회가 10분 미만 창에서 **120건을 넘으면** `{ action: 'propose_revocation', reasonCode: 'burst_read' }`를 돌려줍니다. 유효한 기기 ID가 있으면 결과에 그 한 기기를 `target.deviceId`로 담고, 없는 최소 사건 형식에서는 표본처럼 가명 `subject`를 담습니다. `signals.source`나 네트워크·지역 신호는 필수가 아닙니다. 120건은 제안하지 않습니다. 다른 사용자·기기를 합산하거나 10분 경계 밖의 사건을 같은 묶음으로 세지 않습니다. 기기 ID는 판정 요청 계약의 16자리 소문자 16진수 형식입니다.

이 파일의 사건 모양과 `judge_fixture` 값은 **로컬 연습용**입니다. 브라우저가 보낸 사용자·기기 값을 검증된 값으로 승격하지 않습니다. 운영 반 엔진의 사건 전달과 회수 집행은 별도로 연결·시험해야 합니다. 이 명령의 통과를 실제 접속 차단이나 심판 판정으로 표시하지 않습니다.
