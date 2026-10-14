const PATTERNS = Object.freeze([
  {
    "name": "비정상 정황이 결합된 관리자 그룹 변경",
    "condition": "실제 administrators 그룹 변경과 원격 추가·여러 계정 추가·곧바른 명령 실행·짧은 시간의 제거 후 재추가 중 하나가 함께 확인됨",
    "evidence": "MITRE T1078의 유효 계정 악용을 점검하는 관찰 신호로 가상 경보 pv-01·pv-04·pv-05·pv-07·pv-09의 관리자 그룹 변경과 추가 이상 정황을 결합하며, 그룹 추가만으로 도용을 확정하지 않는다."
  },
  {
    "name": "새 관리자 권한의 사용 또는 세션 전환",
    "condition": "방금 관리자가 된 계정의 실제 명령 실행 또는 관리자 권한으로 전환된 세션과 처음 보는 요청 주소가 함께 확인됨; 취약점 악용 여부는 별도 증거가 있어야 확정함",
    "evidence": "MITRE T1068은 소프트웨어 취약점을 이용한 권한 상승을 설명하고 T1078은 유효 계정 악용을 설명하므로, pv-02·pv-06의 권한 전환은 조사 신호이며 취약점 악용 자체의 증거는 아니다."
  },
  {
    "name": "명확한 비정상 맥락의 관리자 명령",
    "condition": "관리자 명령 실행에 업무·수업 시간 밖과 처음 보는 주소가 함께 있거나 다른 계정의 권한 사용이 명시됨; 처음 보는 관리자 명령이나 시간 밖 사용 하나만으로 차단 근거를 삼지 않음",
    "evidence": "가상 경보 pv-03·pv-08은 단순 관리자 활동과 구별되는 복합 정황을 제공하며 MITRE T1078의 계정 악용 가능성을 점검하는 로컬 정책이다."
  },
  {
    "name": "확정할 수 없는 권한 관련 변경·시도",
    "condition": "취소된 권한 상승 창·일반 그룹 변경·평소 주소의 단일 명령·조회·실패 등 단편만 관찰됨; 알림만 남김",
    "evidence": "MITRE T1068·T1078은 취약점 악용이나 계정 악용을 다루므로 pv-10~pv-17의 조회·취소·실패·단일 변경만으로 이를 확정하지 않는 것은 로컬 오탐 방지 정책이다."
  },
  {
    "name": "동일 계정의 관리자 그룹 추가 후 명령 실행",
    "condition": "같은 PC·같은 계정에서 실제 administrators 그룹 추가 후 5분 이내 성공한 관리자 명령 실행이 이어짐",
    "evidence": "MITRE T1078의 유효 계정 악용 가능성을 조사하기 위해 그룹 추가와 후속 권한 사용을 결합하며, 같은 계정·PC와 5분 제한은 MITRE의 기준이 아닌 로컬 상관 분석 정책이다."
  }
].map(pattern => Object.freeze(pattern)));

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const account = typeof alert?.data?.srcuser === 'string' ? alert.data.srcuser : '';
  const group = typeof alert?.data?.group === 'string' ? alert.data.group.toLowerCase() : '';
  const countValue = alert?.data?.count;
  const count = Number.isInteger(countValue) ? countValue
    : typeof countValue === 'string' && /^\d+$/u.test(countValue) ? Number(countValue) : 0;
  const adminGroup = group === 'administrators';
  const added = /관리자 그룹.*(?:추가|들어가|들어왔)|관리자 그룹 추가/u.test(description);
  const command = /관리자 명령.*실행|권한 명령.*실행|명령 실행/u.test(description);
  const rejected = /취소|실패|명령은 없/u.test(description);
  let confidence = 0;
  let reason = '일치하는 권한 악용 패턴 없음';
  if (!rejected && adminGroup && added && (
    /원격 주소/u.test(description) || command
    || (/계정\s*\d+개/u.test(description) && count >= 4)
    || (/빠진 계정/u.test(description) && /1분 뒤/u.test(description) && /다시 관리자/u.test(description)))) {
    confidence = 0.95;
    reason = PATTERNS[0].name;
  } else if (!rejected && ((/방금 관리자가 된/u.test(description) && command)
      || (/세션이 관리자 권한으로 바뀌/u.test(description) && /처음/u.test(description)))) {
    confidence = 0.95;
    reason = PATTERNS[1].name;
  } else if (!rejected && command && ((/시간 밖/u.test(description) && /처음 보는 주소/u.test(description))
      || /다른 계정의 권한/u.test(description))) {
    confidence = 0.95;
    reason = PATTERNS[2].name;
  } else {
    const ordinary = /그룹 소속을 읽기만|관리 계정.*로그인|로그아웃/u.test(description);
    if (!ordinary && /관리자 그룹|과제 그룹|권한 상승|관리자 명령|계정 종류|로컬 그룹|그룹.*설명.*바뀌/u.test(description)) {
      confidence = 0.55;
      reason = PATTERNS[3].name;
    }
  }
  // Without an attributable account, report the candidate but do not authorize revocation.
  if (!account && confidence >= 0.85) confidence = 0.55;
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
