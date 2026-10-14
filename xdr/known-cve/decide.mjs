const PATTERNS = Object.freeze([
  {
    "name": "머리글의 완전한 JNDI 원격 조회",
    "condition": "data.useragent에 구분자가 닫히고 LDAP 원격 목적지를 가진 완전한 JNDI 조회 구문이 있음",
    "evidence": "Apache CVE-2021-44228 공지의 로그 입력 JNDI 악용에 해당하는 형태로, 가상 경보 kc-01·kc-04·kc-07에서 관찰된다; 기법 분류는 MITRE ATT&CK T1190이다."
  },
  {
    "name": "요청 주소·인자의 완전한 JNDI 원격 조회",
    "condition": "data.url에 구분자가 닫히고 LDAP 원격 목적지를 가진 완전한 JNDI 조회 구문이 있음",
    "evidence": "Apache CVE-2021-44228 공지는 외부 입력의 JNDI 악용을 설명하며 가상 경보 kc-02·kc-03·kc-06·kc-08은 요청 인자 사례를 제공한다; 기법 분류는 MITRE ATT&CK T1190이다."
  },
  {
    "name": "취약점 점검 도구의 의심 흔적",
    "condition": "경보 설명에 취약점 점검 또는 점검 도구의 흔적이 있으나 실제 요청 필드의 완전한 악용 구문은 확인되지 않음; 알림만 남김",
    "evidence": "가상 경보 kc-05에는 점검과 악용 구문이 함께 있지만 kc-13에는 비슷한 도구 이름만 있으므로 도구 흔적 단독으로 악용을 확정하지 않는다."
  },
  {
    "name": "악용을 확정할 수 없는 취약점 관련 흔적",
    "condition": "CVE·JNDI 관련 단어, 라이브러리 언급 또는 불완전한 조회 흔적만 있고 실제 요청 필드의 완전한 악용 구문은 없음; 알림만 남김",
    "evidence": "가상 경보 kc-09~kc-12·kc-14~kc-16은 이름 검색·수업 문서·구문 단편 등의 모호한 사례이며 취약점 악용이나 원격 실행 성공의 증거가 아니다."
  }
].map(pattern => Object.freeze(pattern)));

const COMPLETE_LOOKUP = /\$\{jndi:ldap:\/\/[^\s{}/?#]+(?:[/?#][^\s{}]*)?\}/iu;
const TOOL_HINT = /취약점 점검|점검 도구/u;
const PARTIAL_HINT = /CVE-2021-44228|\bjndi\b|취약점|라이브러리|중괄호|조회 형태가 잘린|원격 조회 구문/iu;

export function decide(alert) {
  const header = typeof alert?.data?.useragent === 'string' ? alert.data.useragent : '';
  const url = typeof alert?.data?.url === 'string' ? alert.data.url : '';
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  let confidence = 0;
  let reason = '일치하는 알려진 악용 패턴 없음';
  if (COMPLETE_LOOKUP.test(header)) {
    confidence = 0.98;
    reason = PATTERNS[0].name;
  } else if (COMPLETE_LOOKUP.test(url)) {
    confidence = 0.98;
    reason = PATTERNS[1].name;
  } else if (TOOL_HINT.test(description)) {
    confidence = 0.65;
    reason = PATTERNS[2].name;
  } else if ([header, url, description].some(value => PARTIAL_HINT.test(value))) {
    confidence = 0.5;
    reason = PATTERNS[3].name;
  }
  const action = confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  return { action, confidence, reason };
}
