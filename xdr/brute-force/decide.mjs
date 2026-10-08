const PATTERNS = Object.freeze([
  Object.freeze({
    name: '짧은 시간의 동일 주소 로그인 실패 연속',
    condition: '같은 출발 주소에서 짧은 시간 동안 로그인 실패가 반복해서 발생합니다.',
    evidence: 'MITRE ATT&CK T1110은 반복적·반복 순환 방식의 비밀번호 추측을 무차별 대입으로 설명합니다.',
  }),
  Object.freeze({
    name: '여러 계정에 같은 비밀번호 대입',
    condition: '같은 출발 주소에서 여러 계정을 대상으로 동일한 비밀번호 시도가 관찰됩니다.',
    evidence: 'MITRE ATT&CK T1110의 탐지 전략 AN1277은 짧은 시간 안에 여러 사용자 계정에 대한 password spraying 또는 무차별 대입 시도를 설명합니다.',
  }),
]);

const NO_MATCH = '일치하는 무차별 대입 패턴 없음';

function safeText(value) {
  return typeof value === 'string' ? value : '';
}

export function decide(alert) {
  const description = safeText(alert?.rule?.description);
  const sourceAddress = safeText(alert?.data?.srcip);
  const account = safeText(alert?.data?.srcuser);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const count = Number.parseInt(alert?.data?.count, 10) || 0;
  const multipleAccounts = typeof alert?.data?.accounts === 'string'
    ? alert.data.accounts.split(',').filter(Boolean).length > 1
    : /여러 계정|서로 다른 계정|계정 \d+개/.test(description);
  const explicitFailure = /실패/.test(description);
  const samePasswordSpray = multipleAccounts && /(?:같은|동일한) 비밀번호/.test(description);
  const describedFailureCount = Number(description.match(/실패(?:가|는)?\s*(\d+)\s*건/)?.[1] ?? 0);
  const shortWindow = /\d+분|\d+초/.test(description);

  let confidence = 0;
  let patternName = NO_MATCH;

  if ((explicitFailure || samePasswordSpray) && sourceAddress && account) {
    if (multipleAccounts) {
      confidence = 0.9;
      patternName = PATTERNS[1].name;
    } else if ((count >= 20 || level >= 10) && (shortWindow || count >= 20)) {
      confidence = 0.9;
      patternName = PATTERNS[0].name;
    } else if (count >= 3 || describedFailureCount >= 3) {
      confidence = 0.65;
      patternName = PATTERNS[0].name;
    }
  }

  const action = confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  return { action, confidence, reason: patternName };
}
