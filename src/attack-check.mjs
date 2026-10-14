// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if ([6, 7, 8, 9, 10, 11, 12].includes(config.step)) return runStep6Checks(config);
  if (config.step !== 1) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}

async function runStep6Checks(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 확인해 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || !app.hostname.endsWith('.vercel.app')) {
    throw new Error('aleph.config.json의 실제 Vercel 배포 주소를 확인해 주세요.');
  }

  const results = [];
  for (const [attackId, path, expectedStatus, description] of [
    ['existing_vault_screen', '/', 200, '기존 자료실 화면'],
    ['anonymous_notes_read', '/api/notes', 401, '비로그인 자료 API 읽기'],
  ]) {
    try {
      const response = await fetch(new URL(path, app), {
        redirect: 'error', signal: AbortSignal.timeout(5000), cache: 'no-store',
        alephEvidence: { caseId: attackId, requestKey: 'read' },
      });
      results.push({ attackId, expected: `${description}: HTTP ${expectedStatus}`,
        observed: `HTTP ${response.status}` });
      await response.body?.cancel();
    } catch {
      results.push({ attackId, expected: `${description}: HTTP ${expectedStatus}`,
        observed: 'network_error' });
    }
  }

  if (config.step >= 10) {
    try {
      const response = await fetch(new URL('/api/restore/00000000-0000-4000-8000-000000000001', app), {
        method: 'GET', redirect: 'error', cache: 'no-store',
        signal: AbortSignal.timeout(5000),
        alephEvidence: { caseId: 'anonymous_note_restore', requestKey: 'read' },
      });
      results.push({ attackId: 'anonymous_note_restore',
        expected: '비로그인 복구 요청: HTTP 401 또는 403; 404는 확인 불가',
        observed: `HTTP ${response.status}` });
      await response.body?.cancel();
    } catch {
      results.push({ attackId: 'anonymous_note_restore',
        expected: '비로그인 복구 요청: HTTP 401 또는 403; 404는 확인 불가',
        observed: 'network_error' });
    }
  }

  if (config.step >= 11) {
    try {
      const response = await fetch(new URL('/api/device/status', app), {
        redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(5000),
        alephEvidence: { caseId: 'anonymous_device_approval', requestKey: 'read' },
      });
      results.push({ attackId: 'anonymous_device_approval',
        expected: '비로그인 기기 승인 확인: HTTP 401, 승인 없음',
        observed: `HTTP ${response.status}` });
      await response.body?.cancel();
    } catch {
      results.push({ attackId: 'anonymous_device_approval',
        expected: '비로그인 기기 승인 확인: HTTP 401, 승인 없음',
        observed: 'network_error' });
    }
  }

  // Local practice has no independently observed HTTP receipt. Keep it out of observed.
  const pending = [
    ['registered_device_read', '운영 등록 기기의 정상 자료 읽기 허용'],
    ['unregistered_device_read', '운영 미등록 기기의 자료 읽기 거부'],
  ];
  if (config.step >= 7) pending.push(
    ['composite_risk_step_up', '운영 복합 이상 요청의 추가 확인'],
    ['engine_verified_step_up', '운영 재확인 뒤 정상 자료 읽기 허용'],
  );
  if (config.step >= 9) pending.push(
    ['normal_read_detection', '운영 정상 조회의 권한 유지'],
    ['unusual_network_burst_revocation_proposal', '운영 조회 폭주 탐지와 회수 제안'],
  );
  results.push(...pending.map(([attackId, expected]) => ({ attackId, expected, observed: 'not_run' })));
  return results;
}
