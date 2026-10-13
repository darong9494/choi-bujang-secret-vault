# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 가상 자료실을 볼 수 있습니다. 화면은 `/api/notes` Vercel 서버 함수에서 Supabase의 가상 메모 네 건을 읽습니다. `/data.json`은 빈 목록만 제공하며 메모를 담지 않습니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

Vercel 프로젝트 설정의 Environment Variables에 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 입력하고 재배포하세요. 두 값은 브라우저 코드에 넣지 않으며, 함수도 키를 응답하거나 로그에 기록하지 않습니다. Supabase `notes` 테이블에는 화면용 가상 메모 네 건이 준비되어 있어야 합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 배포 식별정보 없이 정적 결과물만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 이 빌드는 `public/data.json`에 빈 목록을 생성합니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.


## 6단계: 등록한 기기만 자료실에 들어옵니다

`src/decider.mjs`의 `decide(request)`는 `docs/DECIDER_REQUEST.md`의 `aleph.decision.v1` 요청 중 엔진이 확인해 전달한 사용자 프로젝트 식별정보, 기기 ID·등록 여부, 서비스·메서드·경로만 사용합니다. 등록 여부가 `true`가 아니거나 확인된 식별정보·기기 ID가 유효하지 않으면 `deny`와 `device_not_registered`로 응답합니다. 등록된 기기의 허용된 자료 읽기 경로만 `allow`이며, 그 밖의 경로는 `starter_not_ready`로 거부합니다. 규칙 ID는 `device_registered`입니다.

### 6단계 판정기 확인 순서

1. 저장소 루트에서 `npm run decider:test`를 실행합니다.
2. 등록된 기기의 정상 요청에서 `통과 · 등록 기기의 정상 요청 · allow · approved`가 나오는지 확인합니다.
3. 미등록 기기의 가상 요청에서 `통과 · 미등록 기기의 가상 요청 · deny · device_not_registered`가 나오는지 확인합니다.

별도 접속 프로그램 설치는 필요하지 않습니다. 이 명령은 가상 요청을 사용하는 로컬 연습이며, 운영 엔진 연결이나 심판 판정을 증명하지 않습니다. 미등록 기기 공격 판정은 심판이 맡습니다.

현재 `/api/notes`는 로그인 확인 후 로그인 사용자 소유의 메모를 읽고 씁니다. 하지만 이 API는 `decide()`를 호출하지 않으며, 엔진이 확인한 `deviceRegistered` 요청을 전달받는 연결도 없습니다. 따라서 6단계 판정기 규칙은 로컬 판정 요청에 구현되어 있지만 실제 `/api/notes` 접근에는 아직 적용되지 않습니다. 기존 자료실 주소와 브라우저 화면은 그대로입니다.

## 7단계: 복합 이상 접속은 다시 확인합니다

`step_up_required` 규칙은 엔진 요청의 최근 `risk_signal` 사건(300초 이내·횟수 10 이상), 비정상 네트워크, 이른/늦은 시각(0~5시 또는 23시)이 함께 있을 때 `step_up`을 요청합니다. 지역 값만으로는 거부하거나 추가 확인을 요구하지 않습니다. 요청의 `stepUp.verified`가 참이고 엔진이 확인한 `authAgeSeconds`가 0~900초일 때만 이 가상 조합을 통과시킵니다.

로컬 가상 연습은 `npm run decider:test`입니다. 정상 조합은 `allow`, 복합 이상 조합은 `step_up · step_up_required`, 엔진 검증 재로그인 시각이 있는 가상 요청은 `allow`여야 합니다. 브라우저 위치는 사용하지 않으며, 실제 재로그인 검증은 제공 엔진이 확인한 시각이 전달될 때만 시험할 수 있습니다. 이 연습은 운영 엔진 접속이나 심판 판정이 아닙니다.

현재 제공 계약은 `stepUp.verified`와 `authAgeSeconds` 필드만 정의하며, 같은 로그인 사용자의 새 로그인 확인을 자료 API까지 강제하는 연결은 확인되지 않았습니다. `/api/notes`와 `/api/notes/:id`는 `decide()`를 호출하지 않으므로 추가 확인 전 자료 차단 및 새 로그인 뒤 허용은 미실행입니다. 실제 엔진 연동 전에는 로컬 가상 사건만 확인합니다.

## 보너스 XDR: 무차별 로그인 공격 연습

`xdr/brute-force/patterns.json`은 MITRE ATT&CK T1110 근거가 있는 두 연습 패턴을 담고, `xdr/brute-force/decide.mjs`는 가상 경보를 `block`·`alert`·`record`로 분류합니다. 저장소 루트에서 `npm run xdr:run -- brute-force`를 실행하면 결과를 `xdr/brute-force/result.json`에 갱신합니다. 결과는 fixture를 사용한 로컬 자기 점검이며 실제 ZTNA 차단이나 심판 판정이 아닙니다.
