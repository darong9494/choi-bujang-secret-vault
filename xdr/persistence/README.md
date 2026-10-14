# 지속성 프로그램 검사: 현재 제작 범위

학생 제작 모듈이며 기존 ZTNA 규칙과 제공 ALEPH SDP 엔진의 신원 확인·집행을 대체하지 않습니다. `patterns.json`에 [Windows 서비스 T1543.003](https://attack.mitre.org/techniques/T1543/003/), [예약 작업 T1053.005](https://attack.mitre.org/techniques/T1053/005/), [시작 폴더 T1547.001](https://attack.mitre.org/techniques/T1547/001/) 근거와 수업용 경보 근거를 구분했습니다. 경보의 상위 기법 태그만으로 차단하지 않습니다.

## 단독 경보 판정

`decide.mjs`는 패턴 상수를 갖고 `decide(alert)` 하나만 내보냅니다. 파일·네트워크·패키지 없이 `{action, confidence, reason}`을 계산합니다. 0.85 이상 block, 0.5 이상 alert, 그 미만 record입니다. 서명 미확인을 무서명으로 바꾸지 않고, 임시 파일·높은 경보 수준·PC 이름·계정 하나만으로 차단하지 않습니다. 이유는 고정 패턴 이름이며 경보 원문·주소·계정·파일 경로를 출력하지 않습니다.

실행: `npm run xdr:run -- persistence`. 원본 경보를 보존하고 기존 실행기가 `result.json`을 씁니다. 명확한 복합 근거는 block, 애매한 변경은 alert, 기존 정상 활동은 record여야 합니다. 이는 로컬 가상 시험이며 실제 PC 격리·운영 심판 결과가 아닙니다. 별도 화면 버튼은 없습니다.

## 평소 목록과 사건 결합

`assess-events.mjs`의 `assessEvents(events, {agentName, baselinePaths, now})`는 지정한 PC의 최근 10분 경보만 평가합니다. 평소 목록은 관리자가 확인한 실행 경로 배열을 서버에서 제공합니다. 목록 미제공은 `unavailable`, 각 경로의 비교 불가는 `unknown`입니다. 비어 있는 가상 목록이나 현재 관찰한 경로를 평소 목록으로 자동 등록하지 않습니다. 목록에 없는 변경 항목은 알림이며, 목록에 있더라도 명확한 변조·악용 근거를 무시하지 않습니다.

같은 PC·동일 경로에서 5분 안에 파일 무결성 변경, 명시적 무서명, 임시 실행 경로, 서비스·작업 생성이 함께 있으면 사건을 결합합니다. 다른 PC·경로·시각의 사건은 결합하지 않습니다. 오래되거나 미래·시각 미상의 경보로 격리하지 않습니다. 근거 경보 번호가 없으면 격리 근거로 쓰지 않습니다. 만료는 마지막 근거 사건 시각부터 10분이며 조회할 때마다 연장하지 않습니다.

실제 평소 서비스·작업 이름, 서명·해시 검증 정보는 현재 자료에 없습니다. 현재는 경로 비교와 경보 설명의 명시적 사실만 사용하며 실제 인벤토리·바이너리 서명 검증이 완료됐다고 보고하지 않습니다.

## ZTNA 추가 검사와 PC 범위

서버 호출부는 `check-access.mjs`의 `checkAccess(request, requestAlert, context)`를 사용하고 반드시 반환값의 `proceed`로 진행 여부를 판단합니다. 기존 알려진 CVE 검사와 ZTNA deny·step_up도 유지합니다.

```js
import { checkAccess } from './xdr/persistence/check-access.mjs';
import { respond } from './xdr/persistence/respond.mjs';
for (const alert of serverCollectedPersistenceEvents) {
  await respond(alert, { binding: trustedAgentDeviceBinding });
}
const result = await checkAccess(engineVerifiedRequest, serverCollectedRequestAlert, {
  binding: trustedAgentDeviceBinding,
  events: serverCollectedPersistenceEvents,
  baselinePaths: administratorApprovedPaths,
});
if (!result.proceed) return; // 기존 거부·추가 확인 또는 해당 PC 접속 격리
```

`binding`은 서버가 검증한 `{agentName, deviceId, classId, projectId}` 연결 정보입니다. 경보의 출발 IP·계정을 기기 ID로 추측하거나 브라우저의 주장으로 대체하지 않습니다. 현재 요청의 엔진 기기·반·프로젝트가 모두 맞을 때만 해당 PC의 경보를 적용합니다. 확인 불가이면 `bindingStatus: unverified`이며 PC 격리를 실행했다고 보고하지 않습니다.

명확한 현재 근거가 있으면 `quarantine`에 대상 기기·근거 경보 번호·만료 시각을 반환하고, 같은 PC의 후속 정상 요청도 격리 기간 동안 중단합니다. 다른 PC의 정상 요청과 정상 경보만 있는 PC에는 이 격리를 적용하지 않습니다. 기존 판정 응답 다섯 항목은 `ztna`에 그대로 보존합니다. `notify`는 알림 필요 여부이며 실제 알림 전송 완료가 아닙니다.

이번 범위는 모듈·서버용 결합 함수·로컬 만료형 규칙 저장·가상 시험입니다. 운영 경보 수집·검증된 기기 연결·외부 알림 채널·세션 회수·운영 공용 저장소는 미연결이며 자료 API를 이미 연결했다고 주장하지 않습니다. 사건 결합은 신뢰된 경보를 호출부가 제공해야 하며, 저장한 단독 명확 경보의 거부 규칙은 이후 사건 배열이 비어 있어도 만료까지 적용합니다. 로컬 결정을 엔진의 실제 회수 완료로 보고하지 않습니다.

## 대응 모듈과 만료형 거부 규칙

`respond.mjs`의 `respond(alert, {binding})`가 직접 `decide(alert)`를 호출합니다. 외부에서 주장한 action·confidence는 사용하지 않습니다. 확신도 0.85 이상의 block, 안전한 근거 경보 번호, 신뢰된 PC↔기기 연결, 유효하고 최근인 사건 시각이 모두 있어야 규칙을 만듭니다. 경보 번호는 `ps-01` 같은 짧은 문자 접두사와 숫자 또는 Wazuh 숫자·점 형식만 허용합니다. 연결·번호·시각 미확인은 성공으로 처리하지 않습니다. 오래되거나 미래인 사건도 규칙을 만들지 않습니다.

기본 저장 위치는 `artifacts/persistence-deny-rules.json`입니다. 규칙은 `action: deny`, 반·프로젝트·기기의 SHA-256 범위 지문, 생성 시각, `expiresAt`, `evidenceAlertIds`를 가집니다. 기본 만료는 근거 사건부터 10분이며 최대 1시간입니다. IP·계정 전체를 차단하지 않고, 다른 프로젝트·기기는 일치하지 않습니다. 동일 경보 재전달이나 규칙 조회로 만료를 연장하지 않습니다. 만료된 규칙은 조회에서 제외합니다.

`check-access.mjs`가 매 요청에 이 파일을 조회해 `persistenceDenyRules`에 활성 규칙을 반환하고 `proceed`에 반영합니다. 공격이 확인된 기기의 후속 요청은 일반적인 조회여도 격리 기간 동안 중단합니다. 정상 경보만 있는 기기와 다른 기기의 정상 요청에는 이 규칙을 적용하지 않습니다. 기존 ZTNA 응답 다섯 항목과 알려진 CVE 검사는 유지합니다.

block·alert 후보는 같은 `respond.mjs`에서 `xdr/alerts.log`에 JSON 한 줄씩 추가합니다. `moduleKey: persistence`, 시각·안전한 경보 번호·고정된 패턴 이름·판정·규칙 설치 상태만 남기고 계정·IP·파일 경로·원본 설명·비밀값은 복사하지 않습니다. 기존 다른 모듈의 알림은 덮어쓰지 않습니다. record는 알림을 추가하지 않습니다. 로그와 생성 규칙은 Git에서 제외합니다.

확인 명령: `node --test test/persistence-respond.test.mjs`. 별도 화면 버튼은 없습니다. 시험은 격리된 임시 저장소와 명시적인 가상 기기 연결·시험 시각으로 경보를 재입력하며 원본 경보는 수정하지 않습니다. 정상·모호한 경보의 규칙 생성 0건, 명확한 경보의 지정 기기 제한, 다른 기기 정상 통과, 만료 해제, 재입력 중복 방지를 확인합니다. 기본 경로에 실제 파일을 쓰려면 서버 호출부에서 위 respond 함수를 호출해야 합니다.

파일 저장은 쓰기 가능한 단일 프로세스 환경용이며 프로세스 내 갱신을 직렬화하고 규칙 파일을 임시 파일에서 교체합니다. 읽기·검증·쓰기 실패는 오류로 전달합니다. Vercel 서버 함수의 영속 저장이나 여러 프로세스의 공유 저장을 보장하지 않습니다. 운영에는 엔진의 신뢰된 연결 정보와 공용 저장소·집행 연결이 별도로 필요합니다. `decide.mjs`와 `src/decider.mjs`는 파일 쓰기·추가 규칙 저장을 맡지 않습니다.
