// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step === 6) return runStep6Checks(config);
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
      });
      results.push({ attackId, expected: `${description}: HTTP ${expectedStatus}`,
        observed: `실제 GET ${path} HTTP ${response.status}; ${response.status === expectedStatus ? '기대 상태 일치' : '기대 상태 불일치'}; 응답 본문 미기록` });
      await response.body?.cancel();
    } catch {
      results.push({ attackId, expected: `${description}: HTTP ${expectedStatus}`,
        observed: `실제 GET ${path} 요청을 보냈으나 응답 확인 실패; 미확인` });
    }
  }

  const { decide } = await import('./decider.mjs');
  const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
  const { normal } = fixtureRequests();
  for (const [attackId, deviceRegistered, expected, expectedReason] of [
    ['registered_device_read', true, 'allow', 'approved'],
    ['unregistered_device_read', false, 'deny', 'device_not_registered'],
  ]) {
    const response = await decide({ ...normal, deviceRegistered });
    results.push({ attackId,
      expected: `로컬 가상 요청: ${expected}·${expectedReason}`,
      observed: `로컬 가상 요청 실행: ${response.decision}·${response.reasonCode}; 운영 기기 등록·미등록 공격 판정은 미확인` });
  }
  return results;
}
