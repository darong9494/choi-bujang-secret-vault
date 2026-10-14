const PATTERNS = Object.freeze([
  {
    "name": "요청 머리글의 JNDI 원격 조회 형태",
    "condition": "요청 머리글을 담은 data.useragent에 여닫는 구분자와 LDAP 원격 목적지를 갖춘 완전한 JNDI 조회 구문이 있음; CVE 이름이나 jndi 단어만으로는 일치시키지 않음",
    "action": "block",
    "evidence": "Apache CVE-2021-44228 공지는 공격자가 제어하는 로그 입력의 JNDI 원격 코드 실행 위험을 설명하며, 가상 경보 kc-01·kc-04·kc-07은 머리글 형태를 보여 준다; 공격 기법 분류는 MITRE ATT&CK T1190이다."
  },
  {
    "name": "요청 인자의 JNDI 원격 조회 형태",
    "condition": "요청 주소를 담은 data.url의 인자에 여닫는 구분자와 LDAP 원격 목적지를 갖춘 완전한 JNDI 조회 구문이 있음; 취약점 이름 검색이나 잘린 문자열만으로는 일치시키지 않음",
    "action": "block",
    "evidence": "Apache CVE-2021-44228 공지는 로그에 전달되는 외부 입력의 JNDI 악용 위험을 설명하며, 가상 경보 kc-02·kc-03·kc-06·kc-08은 요청 인자의 해당 형태를 보여 준다; 공격 기법 분류는 MITRE ATT&CK T1190이다."
  },
  {
    "name": "취약점 점검 도구의 의심 흔적",
    "condition": "경보 설명에 취약점 점검 흔적 또는 점검 도구와 유사한 수업용 프로그램 흔적이 명시됨; 도구 흔적만 있으면 알림으로 두고 완전한 악용 구문이 별도로 있을 때만 위 차단 조건을 적용함",
    "action": "alert",
    "evidence": "가상 경보 kc-05는 점검 흔적과 CVE 형태의 동시 관찰을, kc-13은 도구와 비슷한 프로그램 이름만 있는 사례를 제시한다; 이는 보조 신호이며 MITRE ATT&CK T1190 또는 악용 성공을 단독으로 입증하지 않는다."
  }
].map(pattern => Object.freeze(pattern)));

// Pure string inspection: no lookup evaluation, external access, or input echo.
const REMOTE_LOOKUP = /\$\{jndi:ldap:\/\/[^\s{}/?#]+(?:[/?#][^\s{}]*)?\}/iu;
const LOOKUP_HINT = /\bjndi\b|CVE-2021-44228|조회 형태가 잘린|원격 조회 구문|취약점|라이브러리|중괄호/iu;
const TOOL_HINT = /취약점 점검 흔적|점검 도구/u;

export function decide(alert) {
  const header = typeof alert?.data?.useragent === 'string' ? alert.data.useragent : '';
  const url = typeof alert?.data?.url === 'string' ? alert.data.url : '';
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const queryStart = url.indexOf('?');
  const parameters = queryStart >= 0 ? url.slice(queryStart + 1) : '';
  let confidence = 0;
  let reason = '일치하는 알려진 취약점 악용 패턴 없음';

  if (REMOTE_LOOKUP.test(header)) {
    confidence = 0.98;
    reason = PATTERNS[0].name;
  } else if (REMOTE_LOOKUP.test(parameters)) {
    confidence = 0.98;
    reason = PATTERNS[1].name;
  } else if (TOOL_HINT.test(description)) {
    confidence = 0.65;
    reason = PATTERNS[2].name;
  } else if (LOOKUP_HINT.test(header)) {
    confidence = 0.5;
    reason = PATTERNS[0].name;
  } else if (LOOKUP_HINT.test(url)) {
    confidence = 0.5;
    reason = PATTERNS[1].name;
  } else if (LOOKUP_HINT.test(description)) {
    // A description or keyword is only a partial match, never proof for a block.
    confidence = 0.5;
    reason = PATTERNS[0].name;
  }

  const action = confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  return { action, confidence, reason };
}
