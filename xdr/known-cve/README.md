# 알려진 취약점 요청 검사

학생 제작 부품이며 ALEPH SDP 엔진과 기존 학생 ZTNA 판정 규칙을 대체하지 않습니다. 공개 근거는 [Apache CVE 공지](https://logging.apache.org/security.html#CVE-2021-44228), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228), [MITRE T1190](https://attack.mitre.org/techniques/T1190/)이고 `patterns.json`에 검사 정책과 출처를 기록했습니다.

`decide(alert)`는 기존 연습 경보의 `data.url`·`data.useragent`에서 완전한 리터럴 원격 조회 형태를 확인하면 `block`을 반환합니다. 관련 단어·불완전한 흔적·검사 자료 부족은 `alert`, 지원하는 악용 형태가 없는 일반 요청은 `record`입니다. 경보 수준·반복 횟수만으로 차단하지 않습니다. 반환은 `action`·`confidence`·`reason` 세 항목이며 입력·주소·계정·메모 본문을 이유에 복사하지 않습니다. 확신도는 정책 값이며 측정한 통계 확률이 아닙니다.

실행: `npm run xdr:run -- known-cve`. 기존 가상 경보를 수정하지 않고 `result.json`에 요약을 씁니다. 정상 요청은 `record`, 모호한 흔적은 `alert`, 명확한 악용 형태는 `block`이어야 합니다. 외부 접속·원격 조회·명령 실행은 하지 않습니다. 이 결과는 로컬 가상 시험이며 운영 차단·심판 통과 기록이 아닙니다. 별도 화면 버튼은 없습니다.

## ZTNA에 추가하는 순서

서버 호출부에서 기존 계약의 요청과 같은 요청에서 수집한 경보를 별도 인자로 전달합니다. 브라우저가 주장하는 경보 결과를 신뢰하지 않습니다.

```js
import { checkAccess } from './xdr/known-cve/check-access.mjs';
import { respond } from './xdr/known-cve/respond.mjs';
await respond(serverCollectedAlert);
const result = await checkAccess(engineVerifiedRequest, serverCollectedAlert);
if (!result.proceed) {
  // 기존 deny·step_up 처리 또는 명확한 악용 요청 차단. 원본 입력은 기록하지 않음.
  return;
}
// 기존 로그인·소유자·경로 검사도 유지한 뒤 요청 처리.
```

`ztna`는 기존 `decide(request)`의 응답 다섯 항목을 그대로 유지합니다. 검사 결과는 별도 `inspection`이며, `proceed`는 기존 판정이 `allow`이고 검사 결과가 `block`이 아닐 때만 참입니다. `alert`는 알림 대상으로 전달하되 이 검사만으로 차단하지 않습니다. 기존 `deny`·`step_up`을 허용으로 바꾸지 않습니다. 호출부는 계속 진행 여부를 반드시 `proceed`로 판단해야 합니다.

현재 제공한 것은 이 결합 함수·로컬 대응 저장소·로컬 시험입니다. 운영 엔진의 경보 전달·집행 호출부에는 아직 연결되지 않았으며 자료실 API가 이 함수를 이미 호출한다고 주장하지 않습니다. 원문이 없는 기존 요청의 쿼리 지문에서 악용 구문을 추측하지 않습니다. 인코딩·난독화 변형 탐지는 지원하지 않으며 이 부품만으로 전체 CVE 방어나 취약 라이브러리 수정 완료를 판단하지 않습니다.

## 만료형 거부 규칙과 알림 기록

`respond.mjs`가 서버에서 받은 경보를 `decide()`로 직접 재판정합니다. 외부에서 전달한 `action`·`confidence` 주장은 사용하지 않습니다. `block`이면서 확신도 0.85 이상이고 안전한 근거 경보 번호가 있을 때만 추가 거부 규칙을 저장합니다. 경보 번호는 `kc-01` 같은 짧은 문자 접두사·숫자 또는 Wazuh의 숫자·점 형식만 허용하며, 누락·비정상 번호는 규칙을 만들지 않고 가린 알림으로 남깁니다.

규칙은 `artifacts/known-cve-deny-rules.json`에 저장합니다. `action: deny`, 악용 구문이 확인된 필드의 SHA-256, 생성·만료 시각, `evidenceAlertIds`를 포함합니다. 기본 만료는 10분이며 최대 1시간입니다. 주소·계정 전체를 막거나 원문을 저장하지 않습니다. 같은 경보의 재입력은 규칙을 중복 생성하거나 만료를 연장하지 않습니다. 만료된 규칙은 매칭에서 제외됩니다. 명확한 악용 형태에 대한 즉시 검사는 만료와 별개로 계속 적용합니다.

`check-access.mjs`가 추가 규칙을 조회하고 `denyRules`에 일치한 활성 규칙을 반환합니다. 계속 진행하려면 기존 판정이 `allow`이고, 즉시 검사에서 `block`이 아니며, 활성 추가 규칙과도 일치하지 않아야 합니다. 기존 `src/decider.mjs`의 규칙·응답 계약은 변경하지 않습니다.

`block`·`alert` 알림은 `respond.mjs`에서 `xdr/alerts.log`에 JSON 한 줄씩 추가합니다. 시각·안전한 근거 번호·판정·고정된 패턴 이름·추가 규칙 수만 기록하며 주소·계정·요청 원문·비밀값은 기록하지 않습니다. 일반 `record` 결과는 알림 로그를 만들지 않습니다. 규칙과 로그는 Git에서 제외합니다.

확인 명령은 `node xdr/known-cve/respond.mjs --fixture`입니다. 별도 화면 버튼 없이 터미널에서 실행하며, 실제 로컬 규칙과 알림 파일을 만듭니다. 가상 경보 재입력 시험은 `node --test test/known-cve-respond.test.mjs`입니다. 기존 ZTNA 정상 요청과 결합했을 때 명확한 공격 8건만 차단되고, 모호한 8건과 정상 8건은 이 추가 검사로 차단되지 않아야 합니다.

저장소는 파일 쓰기가 가능한 단일 프로세스용입니다. 같은 파일의 프로세스 내 동시 처리는 직렬화하고 규칙 파일은 임시 파일에서 교체합니다. 여러 프로세스·Vercel 서버 함수의 영속 저장을 보장하지 않으며, 운영 사용에는 엔진의 공용 저장소와 신뢰된 경보 연결이 별도로 필요합니다. 읽기·검증·쓰기 실패는 성공으로 처리하지 않고 오류를 전달합니다.
