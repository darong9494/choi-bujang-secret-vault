const PATTERNS = Object.freeze([
  {
    "name": "의심 근거가 결합된 서비스 등록·변조",
    "condition": "서명 없는 새 서비스·실행 파일 변경과 임시 실행 경로가 결합되거나, 원격 서명 없는 서비스 등록이 반복되거나, 평소 목록에 없는 서비스의 재시작 지속성이 임시 경로와 결합됨",
    "evidence": "MITRE T1543.003은 서비스를 생성·변조해 지속 실행하는 기법을 설명하며 가상 경보 ps-01·ps-04·ps-06·ps-08은 복합 근거 사례다."
  },
  {
    "name": "의심 근거가 결합된 예약 작업",
    "condition": "임시 실행 경로의 예약 작업이 처음 관찰되고 수업 시간 밖에 실행되거나, 임의 작업 이름을 사용하거나, 시작 프로그램과 같은 임시 실행 파일을 함께 가리킴",
    "evidence": "MITRE T1053.005는 예약 작업을 통한 지속 실행을 설명하며 가상 경보 ps-02·ps-05·ps-07은 복합 근거 사례다."
  },
  {
    "name": "평소 목록에 없는 실행 파일의 시작 폴더 추가",
    "condition": "시작 폴더에 평소 목록에 없는 프로그램이 추가됐다는 경보와 실제 Startup 실행 파일 경로가 함께 있음",
    "evidence": "MITRE T1547.001은 시작 폴더의 지속 실행을 설명하며 가상 경보 ps-03은 새 항목 추가와 해당 경로를 함께 제공한다."
  },
  {
    "name": "확정할 수 없는 지속성 관련 변경",
    "condition": "서명 미확인·임시 파일·서비스 설명 변경·수업용 작업 등 단편만 있고 복합 악용 근거가 부족함; 알림만 남김",
    "evidence": "가상 경보 ps-09~ps-16은 정상 수업 활동 또는 근거가 부족한 변경이므로 단일 신호로 악용을 확정하지 않는 정책의 근거다."
  },
  {
    "name": "파일 무결성 변경과 지속 실행 등록의 결합",
    "condition": "같은 PC·같은 실행 경로에서 5분 이내 파일 무결성 변경·명시적 무서명·서비스 또는 작업 생성·임시 경로가 함께 확인됨",
    "evidence": "MITRE T1543.003·T1053.005의 실행 파일과 등록 변경을 결합하는 보수적 로컬 정책이며 단독 파일 생성 경보만으로 격리하지 않는다."
  },
  {
    "name": "검증된 평소 목록에 없는 변경 항목",
    "condition": "관리자가 제공한 평소 목록이 있고 새로 생성·변경된 실행 경로가 목록에 없음; 이 차이만으로는 알림만 남김",
    "evidence": "과제의 평소 목록 대조 요구를 구현한 정책이며 승인 목록에 없다는 사실 자체는 악성 또는 격리의 증거가 아니다."
  }
].map(pattern => Object.freeze(pattern)));

const TEMP_EXECUTABLE = /[\\/]temp[\\/].+\.(?:exe|dll|sys|cmd|bat|ps1|vbs|lnk)$/iu;
const STARTUP_EXECUTABLE = /[\\/]startup[\\/].+\.(?:exe|cmd|bat|ps1|vbs|lnk)$/iu;

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const path = typeof alert?.data?.path === 'string' ? alert.data.path : '';
  const temporary = TEMP_EXECUTABLE.test(path);
  const unsigned = /서명 없는|서명이 없(?:습니다|음)|서명되지 않/u.test(description);
  const service = /서비스/u.test(description);
  const serviceChanged = /새 서비스|서비스 등록|서비스 실행 파일이 바뀌|평소 목록에 없는 서비스/u.test(description);
  const repeatedRemote = /원격 주소/u.test(description) && /서비스 등록/u.test(description)
    && /연속/u.test(description) && /^\d+$/u.test(String(alert?.data?.count ?? ''))
    && Number(alert.data.count) >= 3;
  let confidence = 0;
  let reason = '일치하는 지속성 악용 패턴 없음';
  if (service && ((serviceChanged && unsigned && temporary)
      || (unsigned && repeatedRemote)
      || (temporary && /평소 목록에 없는 서비스/u.test(description) && /다시 켜도 남/u.test(description)))) {
    confidence = 0.95;
    reason = PATTERNS[0].name;
  } else if (/예약 작업/u.test(description) && temporary
      && ((/처음 보는/u.test(description) && /시간 밖/u.test(description))
        || /이름이 임의 문자열/u.test(description)
        || (/시작 프로그램/u.test(description) && /같은 임시 파일/u.test(description)))) {
    confidence = 0.95;
    reason = PATTERNS[1].name;
  } else if (STARTUP_EXECUTABLE.test(path) && /시작 폴더/u.test(description)
      && /평소 목록에 없는/u.test(description) && /추가/u.test(description)) {
    confidence = 0.9;
    reason = PATTERNS[2].name;
  } else {
    const ordinary = /평소 시각에 그대로|기존.*서명된 채|목록을 읽기만|기존 예약 작업.*마쳤/u.test(description);
    if (!ordinary && /서비스|예약 작업|시작 항목|시작 폴더|시작 프로그램|실행 파일|무결성/u.test(description)) {
      confidence = 0.55;
      reason = PATTERNS[3].name;
    }
  }
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
