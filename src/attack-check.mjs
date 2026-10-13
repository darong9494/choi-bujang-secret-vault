// Only responses to these exact fetches count as observed checks.
// alephEvidence is runner metadata, not an HTTP header or query parameter.
const TEST_ID = '00000000-0000-4000-8000-000000000001';

async function probe(base, path, attackId, headers = {}) {
  try {
    const response = await fetch(new URL(path, base), {
      headers: { Accept: 'application/json', ...headers },
      redirect: 'manual', signal: AbortSignal.timeout(5000),
      alephEvidence: { caseId: attackId, requestKey: 'read' },
    });
    const body = await response.text();
    let ready;
    try { ready = JSON.parse(body)?.ready; } catch { ready = undefined; }
    const rawId = response.headers.get('x-vercel-id');
    const requestId = typeof rawId === 'string' && /^[a-zA-Z0-9:._-]{1,100}$/u.test(rawId)
      ? rawId : null;
    return { ran: true, status: response.status, bodyBytes: Buffer.byteLength(body),
      ready, requestId, hasNotes: /"(?:content|body)"\s*:/u.test(body) };
  } catch {
    return { ran: false };
  }
}

function recorded(attackId, stage, expected, response, accepts) {
  // fetch was called, but no response could be verified. Keep this distinct from an unsent check.
  if (!response.ran) return { attackId, stage, expected, observed: 'network_error', result: 'not_run' };
  const observed = `HTTP ${response.status}; bodyBytes=${response.bodyBytes}`
    + (typeof response.ready === 'boolean' ? `; jsonReady=${response.ready}` : '')
    + (response.requestId ? `; requestId=${response.requestId}` : '');
  return { attackId, stage, expected, observed,
    result: accepts(response) ? 'blocked' : 'breached' };
}

function unrun(attackId, stage, expected) {
  return { attackId, stage, expected, observed: 'not_run', result: 'not_run' };
}

export async function runAttackChecks(configOrUrl) {
  const config = typeof configOrUrl === 'object' && configOrUrl !== null ? configOrUrl : null;
  const base = new URL(config?.publicAppUrl ?? configOrUrl);
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash
      || base.pathname !== '/' || !base.hostname.endsWith('.vercel.app')) {
    throw new Error('실제 Vercel HTTPS 배포 주소를 확인해 주세요.');
  }

  if (config?.step === 1) {
    const response = await fetch(new URL('/data.json', base), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let visible = false;
    if (response.ok) {
      try {
        const data = await response.json();
        visible = data?.sampleMarker === config.sampleMarker
          && Array.isArray(data.notes) && data.notes.length > 0;
      } catch { visible = false; }
    }
    return [{ attackId: 'anonymous_note_read', stage: 1,
      expected: '비로그인 화면에서 가상 메모를 확인',
      observed: `HTTP ${response.status}; ${visible
        ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임'
        : '비로그인 요청에서 확인 표시가 보이지 않음'}`,
      result: visible ? 'blocked' : 'breached' }];
  }

  const checks = [
    ['existing_vault_screen', 1, '/', '자료실 공개 화면 HTTP 200', {}, r => r.status === 200],
    ['anonymous_notes_read', 3, '/api/notes', '비로그인 메모 HTTP 401', {}, r => r.status === 401 && !r.hasNotes],
    ['anonymous_note_restore', 10, `/api/restore/${TEST_ID}`, '비로그인 복원 경로 거부', {},
      r => [401, 403, 404].includes(r.status) && !r.hasNotes],
    ['anonymous_device_approval', 11, '/api/device/status', '비로그인 기기 승인 거부', {},
      r => r.status === 401 && !r.hasNotes],
    ['forged_login_token', 3, '/api/notes', '위조 토큰 거부', { Authorization: 'Bearer a.b.c' },
      r => r.status === 401 && !r.hasNotes],
    ['query_identity_spoof', 4, `/api/notes?user_id=${TEST_ID}`, '쿼리 신원 위조 거부', {},
      r => r.status === 401 && !r.hasNotes],
  ];
  const attempts = [];
  for (const [id, stage, path, expected, headers, accepts] of checks) {
    attempts.push(recorded(id, stage, expected, await probe(base, path, id, headers), accepts));
  }

  // Fixed virtual inputs are executed through the deployed API so each case has one HTTP receipt.
  for (const [id, stage, expected] of [
    ['registered_device_read', 6, '등록 기기 가상 요청 허용'],
    ['unregistered_device_read', 6, '미등록 기기 가상 요청 거부'],
    ['composite_risk_step_up', 7, '복합 이상 가상 요청 재확인'],
    ['engine_verified_step_up', 7, '재확인된 가상 요청 허용'],
    ['normal_read_detection', 9, '정상 조회 가상 사건 관찰'],
    ['unusual_network_burst_revocation_proposal', 9, '조회 폭주 가상 사건 회수 제안'],
  ]) {
    const response = await probe(base, `/api/checks?case=${id}`, id);
    attempts.push(recorded(id, stage, expected, response,
      r => r.status === 200 && r.ready === true));
  }

  for (const [id, stage, expected] of [
    ['registered_device_read_live', 11, '등록된 실기기 메모 읽기'],
    ['other_owner_read_live', 8, '다른 실계정 메모 접근 거부'],
    ['engine_revocation_live', 9, '엔진 권한 회수 집행'],
    ['engine_restore_live', 10, '엔진 검증 사본 복원'],
    ['engine_audit_live', 10, '엔진 감사 이력 보존'],
  ]) attempts.push(unrun(id, stage, expected));
  return attempts;
}
