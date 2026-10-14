# BYTE BACK 나의 자료실 · 12단계

가상 메모 자료실과 학생 코드의 탈환 작전실입니다. [Vercel 배포](https://choi-bujang-secret-vault-beta.vercel.app/) · [GitHub 저장소](https://github.com/darong9494/choi-bujang-secret-vault). 심판 통과 여부는 이 화면이 아니라 제출 포털의 판정으로 확인합니다.

## 출처와 책임

| 출처 | 실제 맡는 일 |
|---|---|
| 학생이 만든 코드 | `public/` 접속 화면, `api/` 자료실·점검 함수, `src/decider.mjs` 판정 규칙, `src/detect.mjs` 탐지 제안, `src/attack-check.mjs` 자기 점검 |
| 시작 틀 | 배포 식별정보 생성, `scripts/bundle.mjs` 제출 묶음 구조, 기초 가상 자료와 계약 문서 |
| 제공 엔진 | ALEPH SDP 엔진의 신원·기기 확인, 판정기 호출과 집행, 실제 권한 회수, 백업 복원, 감사 기록 보관. 엔진 코드는 이 저장소에 없음 |
| 외부 서비스 | Vercel은 화면·서버 함수를 배포하고 Supabase는 가상 메모·학생 로그인을 제공합니다. 두 서비스의 응답을 엔진 판정으로 바꾸지 않습니다. |

## 설치·실행·중지·복구

1. 설치: 이 저장소를 clone하고 Node.js 22 이상에서 `npm install`을 실행합니다. Vercel 프로젝트에는 `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` 또는 `SUPABASE_ANON_KEY`, `SUPABASE_SECRET_KEY`를 비밀 환경변수로 설정합니다. 값은 Git에 넣지 않습니다.
2. 실행: Vercel에 `main`을 배포합니다. 공개 화면은 `/`, 서버 함수는 `/api/`입니다. `npm run build -- --local`은 로컬 정적 빌드만 확인합니다.
3. 점검: 커밋·push와 배포 커밋 확인 후 `npm run bundle`을 실행합니다. 제출 파일 `artifacts/submission.json`과 `bundle-notes.json`은 Git에서 제외합니다. 작전실의 `지금 다시 확인`은 배포 API에 자기 점검 요청을 보내고 이번 응답으로 수치를 갱신합니다.
4. 중지: Vercel 프로젝트에서 배포를 중지하거나 이전 배포로 롤백합니다.
5. 복구: 검증된 커밋을 확인해 다시 배포하고 정상·거부 요청을 다시 보냅니다. 제공 엔진의 백업·감사 기록은 학생 저장소를 다시 배포하는 것으로 복구되지 않습니다.

## 현재 동작

로그인한 학생의 메모 API는 소유자만 읽고 변경할 수 있습니다. 비로그인 자료 요청은 거부됩니다. 설치형 화면은 manifest와 오프라인 안내를 제공하고, 기기 승인 전에는 메모를 화면에서 요청하거나 표시하지 않습니다. 운영 엔진의 기기 등록 정보를 서버가 받는 계약은 없어서 현재 기기 상태 함수는 승인 전으로 응답합니다.

판정기 `device_registered`, `resource_scope_access`, `step_up_required`와 탐지기의 `burst_read`는 가상 입력에서 실행됩니다. 실제 엔진의 기기 승인·재확인·권한 회수 집행 결과로 간주하지 않습니다. 10단계 복구 경로는 설정에 선언했으며 검증 사본 복원과 감사 기록은 엔진 책임입니다. 학생 코드가 임의의 메모 사본을 운영 백업처럼 쓰지 않습니다.

## 12단계 자기 점검과 작전실

`src/attack-check.mjs`는 각 `attackId`당 실제 `fetch` 한 번을 보냅니다. `alephEvidence`의 `caseId`와 `requestKey`는 점검 실행기의 연결 정보이며 HTTP 헤더·URL에 넣지 않습니다. 응답을 받으면 `HTTP 상태`, 본문 바이트 수와 제공된 요청 ID만 기록합니다. 요청했으나 응답을 확인하지 못하면 `observed: "network_error"`, `result: "not_run"`으로 기록합니다. 엔진 연결이 없어 요청 자체를 보내지 않은 항목만 `observed: "not_run"`, `result: "not_run"`입니다. 고정 가상 입력은 `/api/checks?case=...`를 통해 학생 판정기·탐지 코드가 실행하고, 출처를 `학생 판정기·탐지 가상 연습`으로 표시합니다.

| 종류 | 확인하는 것 | 출처 |
|---|---|---|
| 정상 요청 | 공개 화면 HTTP 200 | 학생 앱·Vercel 실측 |
| 금지 요청 | 비로그인 메모, 위조 토큰·쿼리 신원, 기기 상태, 복원 경로의 거부 응답 | 학생 API·Vercel 실측 |
| 가상 규칙·탐지 | 등록·미등록 기기, 복합 이상·재확인, 정상 조회·조회 폭주 | 학생 코드가 만든 고정 가상 입력 |
| 미실행 | 등록된 실기기 자료 읽기, 타인 메모, 엔진 권한 회수·복원·감사 | 제공 엔진 기록 미연결 |

`api/checks.js`와 `npm run bundle`은 같은 `runAttackChecks(config)`로 점검합니다. 작전실은 과거의 `src/ops-record.json` 대신 이번 조회에서 받은 HTTP 응답으로 행과 합계를 함께 만듭니다. 각 요청은 5초 안에 응답을 확인하며, 응답 미확인과 엔진 미연결 항목은 미실행으로 남깁니다. 화면 조회에 실패하면 이전 수치도 지웁니다. `blocked`는 학생 자기 점검의 기대 응답이라는 뜻이며 운영 심판의 통과 판정이 아닙니다. Vercel이 제공한 요청 ID가 있으면 행에 표시합니다. 메모 본문, 토큰, 기기 키는 점검 기록에 넣지 않습니다.

가산점 조건은 Node.js 22 이상에서 새 설치가 성공하고, 판정기가 계약의 요청 이름·응답 다섯 항목과 `RULE_IDS`를 지키고, 설정의 `step`이 12인 것입니다. `npm run decider:test`는 가상 요청 연습입니다. 100점 여부는 기본 조건까지 포함한 재제출 판정에서 확인하세요. 회귀 검증은 `node --test test/checks.test.mjs`로 실행합니다.

이전 단계의 상세 설명은 [docs/STEP_RECORDS.md](docs/STEP_RECORDS.md)에 보존했습니다. 요청·응답 형식은 [docs/DECIDER_REQUEST.md](docs/DECIDER_REQUEST.md), 탐지 가상 사건 형식은 [docs/DETECT_EVENTS.md](docs/DETECT_EVENTS.md)를 따릅니다.
