const PATTERNS = Object.freeze([
  Object.freeze({
    name: '요청 인자의 SQL 구문',
    condition: 'HTTP 요청 인자에 SQL 키워드·연산자·주석 구문이 결합되어 데이터베이스 질의에 영향을 주려는 형태가 있습니다.',
    evidence: 'MITRE ATT&CK T1190은 공개 웹·데이터베이스를 노린 SQL injection을 초기 접근 사례로 설명합니다.',
    signal: /\b(?:union\s+select|select\b.{0,60}\bfrom|insert\s+into|update\b.{0,40}\bset|delete\s+from|drop\s+table|(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?|sql(?:i|\s+injection)?)\b|sql\s*(?:구문|주입)/i,
  }),
  Object.freeze({
    name: '요청 인자의 script 태그',
    condition: 'HTTP 요청 인자에 script 태그 표식이 있어 스크립트 삽입 가능성을 살펴볼 신호가 있습니다.',
    evidence: 'MITRE ATT&CK T1190 탐지 전략 DET0080은 공개 앱을 향한 crafted HTTP 입력을 살피며, script 태그 표식만으로 악용 성공을 단정하지 않습니다.',
    signal: /<\s*script\b|&lt;\s*script\b|script\s*(?:tag|태그)|스크립트\s*(?:태그|삽입)/i,
  }),
  Object.freeze({
    name: '요청 인자의 경로 거슬러 올라가기 반복',
    condition: 'HTTP 요청 인자에 ../ 경로 이동 표식이 반복되어 상위 경로 접근을 시도하는 형태가 있습니다.',
    evidence: 'MITRE ATT&CK T1190의 캠페인 C0017 사례는 directory traversal 취약점을 악용해 초기 접근한 일을 기록합니다.',
    signal: /(?:\.\.[/\\]){2,}|(?:%2e){2}(?:%2f|%5c)|(?:directory|path)\s+traversal|경로.{0,12}(?:거슬러|상위)|상위.{0,12}경로/i,
  }),
]);

function normalizeInput(value) {
  let text = typeof value === 'string' ? value.replace(/\+/g, ' ') : '';
  for (let pass = 0; pass < 3; pass += 1) {
    try {
      const decoded = decodeURIComponent(text);
      if (decoded === text) break;
      text = decoded;
    } catch {
      break;
    }
  }
  return text.replace(/&lt;/gi, '<').replace(/&gt;/gi, '>');
}

export function decide(alert) {
  const input = normalizeInput(`${alert?.data?.url ?? ''} ${alert?.rule?.description ?? ''}`);
  const matches = PATTERNS.filter((pattern) => pattern.signal.test(input));
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const count = Number.parseInt(alert?.data?.count, 10) || 0;
  const repeatedHighRisk = level >= 10 && count >= 8;
  const lowConfidenceWazuhSignal = level >= 5 && count >= 1;

  const confidence = repeatedHighRisk ? 0.9 : (matches.length > 0 || lowConfidenceWazuhSignal) ? 0.65 : 0;
  const action = confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  const reason = matches.length > 0
    ? matches.map((pattern) => pattern.name).join(' · ')
    : repeatedHighRisk
      ? '반복된 고위험 Wazuh 웹 경보'
      : lowConfidenceWazuhSignal
        ? '추가 확인이 필요한 저신뢰 Wazuh 웹 경보'
        : '일치하는 주입 패턴 없음';

  return { action, confidence, reason };
}
