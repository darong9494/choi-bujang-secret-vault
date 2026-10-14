// Inspect strings only. Never evaluate lookups, contact a destination, or echo input.
const REMOTE_LOOKUP = /\$\{jndi:ldap:\/\/[^\s{}/?#]+(?:[/?#][^\s{}]*)?\}/iu;
const LOOKUP_HINT = /\bjndi\b|CVE-2021-44228|조회 형태가 잘린|원격 조회 구문/iu;
const MAX_LENGTH = 16384;

export function decide(alert) {
  const values = [alert?.data?.url, alert?.data?.useragent];
  const fields = values.filter(value => typeof value === 'string');
  // Oversized input cannot be fully inspected by this bounded signature check.
  if (fields.some(value => value.length > MAX_LENGTH)) {
    return { action: 'alert', confidence: 0.5, reason: '검사 길이 초과: 추가 확인 필요' };
  }
  if (fields.some(value => REMOTE_LOOKUP.test(value))) {
    return { action: 'block', confidence: 0.98,
      reason: 'CVE-2021-44228: 완전한 JNDI LDAP 원격 조회 형태 · T1190' };
  }
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description.slice(0, MAX_LENGTH) : '';
  if (fields.some(value => LOOKUP_HINT.test(value)) || LOOKUP_HINT.test(description)
      || /취약점|라이브러리|점검 도구|중괄호/u.test(description)) {
    return { action: 'alert', confidence: 0.5,
      reason: '취약점 관련 흔적: 명확한 악용 구문 없어 알림만 기록' };
  }
  if (fields.length === 0) {
    return { action: 'alert', confidence: 0, reason: '요청 검사 필드 없음: 추가 확인 필요' };
  }
  return { action: 'record', confidence: 0, reason: '지원하는 알려진 악용 형태 없음' };
}
