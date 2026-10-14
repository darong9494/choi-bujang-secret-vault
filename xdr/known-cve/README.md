# 알려진 취약점 악용 검사: 현재 제작 범위

학생이 만든 추가 검사 부품입니다. 제공 엔진은 ALEPH SDP 엔진이며 기존 학생 판정기·로그인·소유자·경로 검사와 엔진의 집행을 유지합니다.

공개 근거는 [Apache CVE-2021-44228 공지](https://logging.apache.org/security.html#CVE-2021-44228)와 [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)입니다. `patterns.json`은 이름·조건·근거 한 줄을 담은 문서이고 같은 패턴을 `decide.mjs` 맨 위 상수에 넣었습니다. 가상 경보에서 확인한 보조 신호와 공개 취약점 근거를 구분합니다.

`decide(alert)`는 `data.useragent`·`data.url`의 완전한 리터럴 원격 조회 형태만 높은 확신도로 차단합니다. 점검 도구·취약점 단어·불완전한 흔적은 알림, 일반 이벤트는 기록입니다. 신원·주소·경보 번호·수준·횟수만으로 차단하지 않습니다. 반환은 `{ action, confidence, reason }` 세 항목이며 0.85 이상은 block, 0.5 이상은 alert, 그 미만은 record입니다. 확신도는 패턴 일치 강도이지 측정한 공격 성공 확률이 아닙니다. 이유는 고정 패턴 이름이며 원문·주소·계정·비밀값을 복사하지 않습니다.

판정 파일은 `decide` 하나만 내보내고 다른 파일·패키지를 불러오거나 파일·네트워크에 접근하지 않습니다. 기존 경보 원본은 수정하지 않으며, 경보의 조회 구문을 실행하거나 외부에 전송하지 않습니다.

실행 명령: `npm run xdr:run -- known-cve`. 기존 실행기가 가상 경보를 읽어 `result.json`을 갱신합니다. 별도 화면 버튼은 없습니다. 정상 확인은 일반 이벤트의 record, 차단 확인은 명확한 악용 형태의 block이며 모호한 이벤트는 alert여야 합니다. 이 결과는 로컬 가상 시험이고 운영 차단·심판 통과 기록이 아닙니다.

## ZTNA 결합

```js
import { checkAccess } from './xdr/known-cve/check-access.mjs';
import { respond } from './xdr/known-cve/respond.mjs';
await respond(serverCollectedAlert);
const result = await checkAccess(engineVerifiedRequest, serverCollectedAlert);
if (result.notify) {
  // 서버의 알림 처리부에 고정된 inspection 요약만 전달합니다.
}
if (!result.proceed) {
  // 기존 deny·step_up을 유지하거나 명확한 악용 요청을 중단합니다.
  return;
}
// 나머지 기존 권한 검사를 유지한 뒤 요청을 처리합니다.
```

같은 요청에 대해 서버가 수집한 경보를 별도 인자로 전달합니다. 브라우저가 주장하는 경보·결과로 대체하지 않습니다. `ztna`는 기존 응답 다섯 항목 그대로이고 `inspection`은 별도 검사 결과입니다. `proceed`는 기존 판정이 allow이고 추가 검사에서 block이 아닐 때만 참입니다. 모호한 alert가 기존 정상 요청을 차단하지 않고, 기존 deny·step_up은 record나 alert로 우회하지 못합니다.

현재 범위는 판정 모듈·결합 함수·만료형 거부 규칙·로컬 알림 로그·로컬 시험입니다. 운영 엔진의 경보 공급·집행 호출부는 미연결이며 기존 자료 API가 이 함수를 이미 호출한다고 주장하지 않습니다. 헤더 원문이 없는 기존 판정 계약에 새 필드를 만들지 않습니다.

## 대응 규칙과 알림 파일

`respond.mjs`가 직접 `decide(alert)`를 호출해 차단 후보를 재확인합니다. `block`·확신도 0.85 이상·안전한 근거 경보 번호가 모두 있을 때만 `artifacts/known-cve-deny-rules.json`에 추가 거부 규칙을 저장합니다. 경보 번호는 `kc-01` 같은 짧은 문자 접두사와 숫자, 또는 Wazuh의 숫자·점 형식을 허용합니다. 번호가 없거나 비정상 문자열이면 규칙을 만들지 않고 가린 알림만 남깁니다.

규칙의 `action`은 `deny`이고 실제 악용 필드 이름·SHA-256 지문·생성 시각·`expiresAt`·`evidenceAlertIds`를 포함합니다. 주소·계정 전체를 막거나 요청 원문을 저장하지 않습니다. 기본 유효 시간은 10분이며 최대 1시간입니다. 재입력 시 기존 활성 규칙을 중복 생성하거나 만료를 연장하지 않습니다. 만료된 규칙은 조회에서 제외하며 명확한 공격의 즉시 검사는 별도로 유지합니다.

`check-access.mjs`는 이 추가 규칙을 읽고 일치하는 활성 규칙을 `denyRules`로 반환합니다. 호출부는 반드시 `proceed`를 확인해야 합니다. 기존 판정이 allow이고, 즉시 검사가 block이 아니며, 추가 거부 규칙도 일치하지 않을 때만 계속 진행합니다. 모호한 경보는 알림일 뿐 거부 규칙을 만들지 않습니다. 같은 사용자의 정상 요청에 공격 지문이 없으면 이 규칙으로 막지 않습니다.

`block`·`alert` 알림은 같은 `respond.mjs`에서 `xdr/alerts.log`에 JSON 한 줄씩 추가합니다. 시각·안전한 근거 경보 번호·판정·고정된 패턴 이름·신규 규칙 수만 남기고 주소·계정·요청 원문·비밀값은 복사하지 않습니다. 일반 record 결과는 알림 파일에 쓰지 않습니다. 로그와 생성 규칙은 Git에서 제외합니다.

확인 명령: `node xdr/known-cve/respond.mjs --fixture`. 이 명령은 가상 경보를 흘려 실제 로컬 규칙·알림 파일을 만듭니다. 별도 화면 버튼은 없습니다. 재입력 검증은 `node --test test/known-cve-respond.test.mjs`입니다. 기존 정상 ZTNA 요청과 결합했을 때 명확한 공격 8건만 거부하고 모호한 8건·정상 8건은 이 추가 검사로 차단하지 않아야 합니다.

파일 저장은 쓰기 가능한 단일 프로세스 환경용입니다. 프로세스 내 갱신은 직렬화하고 규칙 파일은 임시 파일에서 교체합니다. 읽기·검증·쓰기 실패는 성공으로 처리하지 않습니다. Vercel 서버 함수의 영속 파일 저장이나 여러 프로세스 간 공유를 보장하지 않으며, 운영 집행에는 제공 엔진의 신뢰된 경보 전달과 공용 저장소 연결이 필요합니다. 기존 ZTNA 규칙과 단독 판정 파일은 변경하지 않습니다.
