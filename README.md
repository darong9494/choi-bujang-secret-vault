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


## 알려진 보안 약점

`/api/notes`는 아직 인증·인가 검사를 하지 않는 공개 주소입니다. 누구나 URL에 직접 요청해 DB의 네 가상 메모를 받을 수 있습니다. 서버 전용 키는 보호되지만, API가 반환하는 메모는 공개 상태이며 다음 단계에서 접근 제어를 추가해야 합니다.

## 보너스 XDR: 무차별 로그인 공격 연습

`xdr/brute-force/patterns.json`은 MITRE ATT&CK T1110 근거가 있는 두 연습 패턴을 담고, `xdr/brute-force/decide.mjs`는 가상 경보를 `block`·`alert`·`record`로 분류합니다. 저장소 루트에서 `npm run xdr:run -- brute-force`를 실행하면 결과를 `xdr/brute-force/result.json`에 갱신합니다. 결과는 fixture를 사용한 로컬 자기 점검이며 실제 ZTNA 차단이나 심판 판정이 아닙니다.

## 보너스 XDR: 웹 주입 공격 연습

`xdr/web-injection/decide.mjs`는 MITRE ATT&CK T1190 근거의 입력 신호로 fixture 경보를 `block`·`alert`·`record` 분류합니다. 저장소 루트에서 `npm run xdr:run -- web-injection`을 실행하면 `xdr/web-injection/result.json`을 갱신합니다. `node xdr/web-injection/respond.mjs`는 차단 후보의 쿼리 지문에 만료 시각과 근거 경보 번호를 붙여 임시 거부 규칙으로 기록하고, 애매한 경보는 `xdr/alerts.log`에 남깁니다. 이 자료는 로컬 fixture 연습이며 실제 운영 배포나 심판 판정이 아닙니다.
