# 권한 상승 검사: 현재 제작 범위

학생 제작 추가 검사이며 기존 ZTNA 규칙과 제공 ALEPH SDP 엔진의 신원 확인·집행을 대체하지 않습니다. 공개 근거는 [권한 상승 악용 T1068](https://attack.mitre.org/techniques/T1068/), [유효 계정 T1078](https://attack.mitre.org/techniques/T1078/)입니다. 경보의 기법 태그는 보조 정보이며 T1068 태그나 관리자 명령만으로 취약점 악용을 확정하지 않습니다.

`patterns.json`에 이름·찾는 조건·근거 한 줄을 적고 같은 상수를 `decide.mjs` 맨 위에 둡니다. 단독 판정 파일은 다른 파일·패키지·네트워크·파일 입출력 없이 `decide(alert)` 하나만 내보냅니다. 반환은 `{action, confidence, reason}`이며 0.85 이상 block, 0.5 이상 alert, 그 미만 record입니다. 관련 신호가 있어도 회수할 계정을 식별할 수 없으면 알림으로만 둡니다. 이유는 고정 패턴 이름이며 원문·주소·계정을 복사하지 않습니다.

실행: `npm run xdr:run -- privilege`. 기존 실행기가 원본 가상 경보를 읽어 `result.json`을 갱신합니다. 명확한 복합 근거는 block, 취소·단발성 실패·일반 그룹 변경 등 모호한 사례는 alert, 정상 로그인·그룹 읽기·정상 관리 계정 활동은 record여야 합니다. 별도 화면 버튼은 없습니다. 결과는 로컬 가상 시험이며 실제 세션 회수·심판 판정이 아닙니다.

## 평소 권한과 사건 결합

`assessEvents(events, {agentName, account, knownAdminAccounts, now})`는 같은 PC와 같은 계정의 최근 10분 사건만 봅니다. Windows 계정의 대소문자는 무시하지만 도메인·계정 문자열은 분리하거나 추측하지 않습니다. 관리자 평소 목록은 서버가 검증한 배열로 제공합니다. 미제공은 unavailable·unknown이며 관찰 계정이나 이름의 admin 글자를 보고 목록을 만들지 않습니다. 목록에 있다는 이유로 명확한 악용 근거를 무시하지 않습니다.

관리자 그룹 추가 후 5분 안에 실제 관리자 명령 실행이 이어지면 두 사건을 결합합니다. 다른 계정·PC·역순·실패·취소는 합산하지 않습니다. 오래된 사건·미래·시각 미확인·근거 번호 누락으로 세션을 제한하지 않습니다. 판단 근거의 마지막 시각부터 10분 동안 추가 접근 제한 결정을 유지하며 같은 사건 조회로 만료를 연장하지 않습니다.

## ZTNA 연결

```js
import { checkAccess } from './xdr/privilege/check-access.mjs';
const result = await checkAccess(engineVerifiedRequest, serverCollectedRequestAlert, {
  binding: trustedAccountSubjectBinding,
  events: serverCollectedPrivilegeEvents,
  knownAdminAccounts: administratorVerifiedAccounts,
  persistence: trustedPersistenceContext,
});
if (!result.proceed) return;
// 기존 나머지 권한 검사와 요청 처리.
```

`binding`은 서버가 검증한 `{agentName, sourceAccount, subjectId, classId, projectId}`입니다. 실제 OS 계정과 엔진의 가명 주체를 문자열 비교나 IP로 추측하지 않습니다. 현재 요청의 주체·반·프로젝트가 모두 맞는 경우에만 그 계정의 사건을 적용합니다. 연결 미확인은 `accountBindingStatus: unverified`이며 회수 완료로 처리하지 않습니다.

명확한 현재 근거는 `revocation`에 `revoke_sessions`·대상 가명 주체·근거 경보 번호·만료를 담고 해당 계정의 요청 진행을 막습니다. 같은 PC의 다른 계정은 대상이 아닙니다. 기존 응답 다섯 항목은 `ztna`에 그대로 남고 기존 ZTNA deny·step_up, 알려진 CVE 검사, PC 격리도 유지합니다. 호출부는 반드시 `proceed`를 확인해야 합니다.

## 차단 후보의 저장과 알림

`respond.mjs`의 `respond(alert, {binding})`를 서버가 수집한 경보와 검증한 계정 연결로 호출합니다. 내부에서 `decide`를 다시 호출하며 외부에서 보낸 action·confidence는 신뢰하지 않습니다. block·0.85 이상, 안전한 경보 번호, 일치하는 PC·계정 연결, 유효한 최근 시각이 모두 있어야 거부 규칙을 만듭니다. 기본 만료는 사건 시각부터 10분이며 재전송으로 연장하지 않습니다. 애매한 경보는 알림만 남기며 정상 이벤트는 거부 규칙을 만들지 않습니다.

거부 규칙은 `artifacts/privilege-deny-rules.json`에 계정·반·프로젝트 범위의 해시와 만료 시각·근거 경보 번호만 저장합니다. block·alert 알림은 `xdr/alerts.log`에 한 줄씩 추가하며 계정·출발 주소·경보 원문을 복사하지 않습니다. 두 파일은 Git 제외 대상입니다. `checkAccess`는 저장된 규칙도 읽으므로 사건 배열이 비어 있어도 해당 계정의 접근 제한이 만료까지 적용됩니다. 테스트용 `createResponder({rulesPath, logPath, clock, ttlMs})`와 `checkAccess`의 `rulesPath`를 지정하면 운영 파일 대신 별도 저장소를 사용할 수 있습니다.

확인 명령: `node --test test/privilege-respond.test.mjs`. 별도 화면 버튼은 없습니다. 명확한 공격은 해당 계정만 거부되고 다른 정상 계정은 통과해야 합니다. 모호한 경보는 알림만 남으며 만료 후에는 기존 판정기에 따라 처리해야 합니다.

실제 평소 권한 목록·OS 계정과 가명 주체 연결·운영 경보 공급·외부 알림 채널·세션 무효화 API는 미연결입니다. `notify`는 알림 필요 여부이며 외부 전송 완료가 아닙니다. `revocation`은 회수 요청용 결정이며 토큰·로그인 세션의 실제 무효화 완료가 아닙니다. 운영 호출부는 반드시 추가 검사 결과를 적용해야 하며 실제 집행을 연결하기 전에는 회수 완료를 보고하지 않습니다. 서버리스 배포의 로컬 파일 저장은 영속 저장을 보장하지 않으므로 운영에서는 서버 전용 영속 저장소 연결이 필요합니다.
