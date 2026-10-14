# 외부 반출 추가 검사

학생 제작 추가 검사이며 기존 ZTNA 규칙과 제공 ALEPH SDP 엔진을 대체하지 않습니다. 근거는 MITRE ATT&CK [T1041](https://attack.mitre.org/techniques/T1041/)·[T1048](https://attack.mitre.org/techniques/T1048/)입니다. 용량 50000000바이트·반복 8회는 로컬 실습 정책이며 MITRE 표준 임계치가 아닙니다. 주소·계정·기법 태그로 정답을 고르지 않습니다.

`decide.mjs`는 패턴을 상수로 포함하며 파일·패키지·네트워크 없이 `decide(alert)` 하나만 내보냅니다. 반환은 `{action, confidence, reason}`이며 0.85 이상 block, 0.5 이상 alert, 그 아래 record입니다. 실제 전송량과 새 목적지·반복·낯선 통로·전체 외부 복사의 복합 근거가 있어야 차단 후보입니다. 새 목적지 또는 큰 용량 하나만으로 차단하지 않습니다. 실패·취소·압축만 수행한 사건도 차단하지 않습니다. 이유에 경보 원문·계정·주소·파일 본문을 복사하지 않습니다.

## 추가 연결

```js
import { checkAccess } from './xdr/exfiltration/check-access.mjs';
const result = await checkAccess(engineVerifiedRequest, serverRequestAlert, {
  binding: trustedDeviceBinding, // {agentName, deviceId, classId, projectId}
  destination: serverVerifiedOutboundIPv4,
  events: serverCollectedTransferEvents,
  baseline: serverVerifiedBaseline, // optional: {destinations: [...IPv4], maxBytes: integer}
  privilege: previousPrivilegeContext,
});
if (!result.proceed) return;
// 기존 나머지 권한 검사와 처리.
```

기존 요청 계약에 새 필드를 만들지 않으며 목적지는 서버가 검증한 별도 context로 전달합니다. 같은 PC·반·프로젝트에 연결된 최근 10분 경보만 반영합니다. 안전한 근거 번호·시각·목적지가 있는 차단 후보 중 현재 목적지와 정확히 같은 주소만 만료까지 제한합니다. 다른 목적지는 추가로 막지 않으며 기존 ZTNA deny·step_up, CVE 차단, PC 격리, 계정 제한은 그대로 적용합니다. 이 단계는 IPv4 목적지만 지원하며 다른 주소 형식은 임의로 변환하거나 차단하지 않습니다.

평소 목록과 최대 전송량은 서버가 검증한 값만 받습니다. 미제공은 unavailable·unknown이며 fixture에서 평소 목록을 추측하지 않습니다. 기준선 이탈만 발견한 경우는 알림 후보이며 자동 차단하지 않습니다. 경보 설명은 교육용 관찰 요약으로 해석하며 실제 운영에서는 신뢰할 수 있는 수집·정규화가 필요합니다.

## 경보 읽기·대응·재현

`node xdr/exfiltration/read-alerts.mjs`는 원본 경보 30건을 시각·출발 주소·계정·규칙 수준·설명의 30줄 JSONL로 추출합니다. 지정하지 않은 필드는 출력하지 않으며 비밀값 의심 문자열은 해당 필드 전체를 가립니다. 원본 경보를 수정하지 않고 판단 모듈에서도 읽기 모듈을 불러오지 않습니다.

`respond.mjs`의 `respond(alert, {binding})`를 서버 경보 수집부에서 호출합니다. binding은 위의 검증된 기기 연결이며 브라우저가 보낸 주장을 그대로 전달하면 안 됩니다. 내부에서 `decide`를 다시 호출하며 외부 action·confidence는 무시합니다. 명확한 block 후보에 유효한 시각·안전한 경보 번호·일치하는 PC 연결·정확한 IPv4 목적지가 모두 있어야 기본 10분 만료의 거부 규칙을 저장합니다. 재전송은 근거 번호를 중복 추가하거나 만료를 연장하지 않습니다. 모호한 경보는 알림만 남기고 정상 이벤트는 규칙을 만들지 않습니다.

규칙은 `artifacts/exfiltration-deny-rules.json`에 기기·반·프로젝트·목적지를 결합한 해시와 만료 시각·근거 번호만 저장합니다. `checkAccess`는 같은 저장소를 읽어 사건 배열이 비어 있어도 후속 요청의 정확한 목적지를 제한합니다. block·alert 알림은 `xdr/alerts.log`에 한 줄씩 추가하며 계정·주소·파일명·원문은 복사하지 않습니다. 규칙과 로그는 Git에서 제외됩니다. 시험은 `createResponder({rulesPath, logPath, clock, ttlMs})`와 `checkAccess`의 동일한 `rulesPath`를 사용해 임시 저장소에서 수행합니다.

실행: `npm run xdr:run -- exfiltration`. 정상 이벤트는 record, 애매한 전송은 alert, 명확한 복합 반출은 block이어야 합니다. 별도 화면 버튼은 없습니다. 읽기·판정·재전송 연결 시험은 `node --test test/exfiltration.test.mjs test/exfiltration-read-alerts.test.mjs test/exfiltration-respond.test.mjs`입니다. 로컬 가상 시험에서 block 10·alert 10·record 10, 정상 이벤트 차단 0건이며 관련 시험 12개가 통과했습니다. 저장점 이름은 「보너스 xdr-06 저장점」입니다.

현재 범위는 판단·최근 사건 수집·로컬 거부 규칙 저장·로그 알림·추가 접근 검사입니다. 운영 전송 경보 공급·실제 목적지 차단 집행은 미연결입니다. `notify`는 알림 필요 여부, `destinationDenial`은 추가 거부 결정이며 외부 알림 전송이나 운영 방화벽 차단 완료가 아닙니다. 운영 호출부가 이 함수를 호출하고 `proceed`를 적용해야 합니다. 서버리스의 로컬 파일 저장은 영속성을 보장하지 않으므로 운영에는 서버 전용 영속 저장소 연결이 필요합니다. 로컬 가상 시험 결과를 심판 판정이나 실제 유출 방지 완료로 보고하지 않습니다.
