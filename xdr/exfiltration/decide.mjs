// The build-time copy of patterns.json is embedded here; runtime has no dependencies.
const PATTERNS = Object.freeze([
  {
    "name": "낯선 목적지로 대량 전송",
    "condition": "실제 전송량 50000000바이트 이상과 처음 보는 목적지가 함께 확인됨",
    "evidence": "MITRE T1041·T1048의 외부 반출 가능성을 점검하는 복합 신호이며 50000000바이트는 MITRE 기준이 아닌 로컬 실습 정책이다."
  },
  {
    "name": "반복·비정상 통로의 대량 전송",
    "condition": "실제 전송량 50000000바이트 이상과 8회 이상 반복, 낯선 포트의 연속 전송, 전체 자료실의 외부 복사 중 하나가 함께 확인됨",
    "evidence": "MITRE T1041은 명령 통로의 반출, T1048은 다른 프로토콜의 반출을 설명하며 반복 횟수·용량 임계치는 로컬 실습 정책이다."
  },
  {
    "name": "확정할 수 없는 전송 이상",
    "condition": "작은 파일의 새 목적지 전송, 평소보다 큰 단일 전송, 실패·전송 전 압축 등 일부 신호만 확인됨",
    "evidence": "MITRE T1041·T1048의 반출 여부를 조사할 후보이며 파일 생성이나 목적지의 낯섦만으로 실제 유출을 확정하지 않는다."
  }
].map(pattern => Object.freeze(pattern)));

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const numeric = value => {
    if (typeof value !== 'number' && !(typeof value === 'string' && /^\d+$/u.test(value))) return null;
    const n = Number(value);
    return Number.isSafeInteger(n) && n >= 0 ? n : null;
  };
  const bytes = numeric(alert?.data?.bytes);
  const count = numeric(alert?.data?.count);
  const destination = typeof alert?.data?.dstip === 'string' ? alert.data.dstip : '';
  const validDestination = /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/u.test(destination)
    && destination.split('.').every(part => Number(part) <= 255);
  const unfamiliar = /처음 보는 (?:목적지|주소)/u.test(description);
  const incomplete = /실패|취소|전송은 아직 없|전송되지 않|전송하지 않/u.test(description);
  const transferred = /나갔|전송됐|전송이|전송은|전송이 같이|전송됐|올라갔|복사됐/u.test(description);
  const large = bytes !== null && bytes >= 50000000;
  let confidence = 0;
  let reason = '일치하는 외부 반출 패턴 없음';
  if (!incomplete && transferred && validDestination && large && unfamiliar) {
    confidence = 0.95;
    reason = PATTERNS[0].name;
  } else if (!incomplete && transferred && validDestination && large && (
    (count !== null && count >= 8 && /반복|같은 목적지/u.test(description))
    || /쓰지 않던 포트.*연속 전송/u.test(description)
    || /자료실 전체.*외부.*복사/u.test(description))) {
    confidence = 0.95;
    reason = PATTERNS[1].name;
  } else if (unfamiliar || large || /평소와 다른 주소|평소보다|파일 수가.*늘|백업처럼|전송.*실패|압축 파일.*(?:만들|다른 주소)|명령 통로|자료.*읽힌 뒤/u.test(description)) {
    confidence = 0.55;
    reason = PATTERNS[2].name;
  }
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
