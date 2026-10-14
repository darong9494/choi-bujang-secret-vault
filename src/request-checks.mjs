const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/iu;
const STATUSES = Object.freeze({ matched: 'matched', mismatch: 'mismatch', inconclusive: 'inconclusive',
  not_run: 'notRun', network_error: 'networkError' });

export function summarizeMeasurements(rows) {
  const summary = { total: rows.length, matched: 0, mismatch: 0, inconclusive: 0, notRun: 0, networkError: 0 };
  for (const row of rows) {
    if (!Object.hasOwn(STATUSES, row.result)) throw new Error('invalid_measurement_result');
    summary[STATUSES[row.result]]++;
  }
  return summary;
}

export async function collectRequestChecks(config, { authorization = null } = {}) {
  const base = new URL(config.publicAppUrl);
  if (base.protocol !== 'https:' || base.username || base.password || base.pathname !== '/' || base.search || base.hash
      || !base.hostname.endsWith('.vercel.app')) throw new Error('invalid_app_url');
  const origin = new URL(config.originalApiUrl);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash) throw new Error('invalid_original_api');
  const rows = [];
  const skip = (id, stage, kind, request, expected, reason) => rows.push({ id, stage, kind, request, expected,
    result: 'not_run', observed: 'not_run', reason, httpStatus: null, requestId: null, attemptedAt: null, checkedAt: null });
  async function probe({ id, stage, kind, path, request = `GET ${path}`, expected, statuses, headers = {}, validate }) {
    const attemptedAt = new Date().toISOString();
    try {
      const response = await fetch(new URL(path, base), { method: 'GET', redirect: 'manual', cache: 'no-store',
        headers: { Accept: 'application/json', ...headers }, signal: AbortSignal.timeout(5000),
        alephEvidence: { caseId: id, requestKey: 'read' } });
      const text = await response.text();
      let json;
      try { json = JSON.parse(text); } catch { json = null; }
      const statusMatches = statuses.includes(response.status);
      const noteInDenial = kind === 'forbidden' && [401, 403].includes(response.status)
        && /"(?:body|content)"\s*:/u.test(text);
      const matches = statusMatches && !noteInDenial && (!validate || validate(json));
      const requestId = response.headers.get('x-vercel-id') ?? response.headers.get('sb-request-id');
      const row = { id, stage, kind, request, expected, httpStatus: response.status,
        requestId: typeof requestId === 'string' && /^[a-zA-Z0-9:._-]{1,100}$/u.test(requestId) ? requestId : null,
        attemptedAt, checkedAt: new Date().toISOString(),
        result: matches ? 'matched' : response.status === 404 ? 'inconclusive' : 'mismatch',
        observed: `HTTP ${response.status}; bodyBytes=${Buffer.byteLength(text)}`,
        reason: matches ? 'expected_response_observed' : response.status === 404 ? 'route_or_resource_not_confirmed' : 'unexpected_response' };
      rows.push(row);
      // Private return value only; response bodies and note identifiers never enter public rows.
      return { row, json };
    } catch {
      rows.push({ id, stage, kind, request, expected, result: 'network_error', observed: 'network_error',
        reason: 'response_unconfirmed', httpStatus: null, requestId: null, attemptedAt, checkedAt: null });
      return null;
    }
  }
  const anonymous = [
    { id: 'normal_public_screen', stage: 1, kind: 'normal_public', path: '/', expected: '공개 화면 HTTP 200', statuses: [200] },
    { id: 'no_public_notes', stage: 2, kind: 'forbidden', path: '/data.json', expected: 'HTTP 200이며 공개 메모 목록이 비어 있음',
      statuses: [200], validate: json => Array.isArray(json?.notes) && json.notes.length === 0
        && !/"(?:body|content)"\s*:/u.test(JSON.stringify(json)) },
    { id: 'anonymous_notes', stage: 3, kind: 'forbidden', path: '/api/notes', expected: '비로그인 자료 읽기 HTTP 401', statuses: [401] },
    { id: 'forged_token', stage: 4, kind: 'forbidden', path: '/api/notes', expected: '위조 토큰 HTTP 401', statuses: [401], headers: { Authorization: 'Bearer a.b.c' } },
    { id: 'spoofed_identity', stage: 4, kind: 'forbidden', path: '/api/notes?user_id=00000000-0000-4000-8000-000000000001',
      expected: '쿼리 신원 위조 HTTP 401', statuses: [401] },
    { id: 'anonymous_restore', stage: 10, kind: 'forbidden', path: '/api/restore/00000000-0000-4000-8000-000000000001',
      request: 'GET /api/restore/:testId', expected: '비로그인 복원 HTTP 401 또는 403; 404는 확인 불가', statuses: [401, 403] },
    { id: 'anonymous_device', stage: 11, kind: 'forbidden', path: '/api/device/status', expected: '비로그인 기기 조회 HTTP 401', statuses: [401] },
  ];
  await Promise.all(anonymous.map(probe));

  // This request intentionally has no API key or user Authorization header.
  await probe({ id: 'direct_original_api', stage: 5, kind: 'forbidden', path: origin.href,
    request: 'GET 원본 자료 API (인증 없음)', expected: '원본 직접 조회 HTTP 401 또는 403', statuses: [401, 403] });

  let device;
  if (authorization) {
    device = await probe({ id: 'normal_device_status', stage: 11, kind: 'normal_status', path: '/api/device/status',
      expected: '로그인 기기 상태 조회 HTTP 200; 승인 여부는 별도 확인', statuses: [200],
      headers: { Authorization: authorization }, validate: json => typeof json?.approved === 'boolean' });
  } else skip('normal_device_status', 11, 'normal_status', 'GET /api/device/status (로그인)', '로그인 기기 상태 HTTP 200', 'login_required');
  let own;
  const ready = device?.row.result === 'matched' && device.json?.approved === true;
  const prereq = !authorization ? 'login_required' : !ready ? 'device_approval_not_confirmed' : null;
  if (ready) {
    own = await probe({ id: 'normal_owned_list', stage: 3, kind: 'normal_protected', path: '/api/notes',
      expected: '서버가 승인한 로그인 기기의 본인 목록 HTTP 200', statuses: [200],
      headers: { Authorization: authorization, 'X-Resource-Id': 'memo:collection' }, validate: Array.isArray });
  } else skip('normal_owned_list', 3, 'normal_protected', 'GET /api/notes (로그인·승인 기기)',
    '본인 목록 HTTP 200', prereq);
  const ownId = own?.row.result === 'matched' && Array.isArray(own.json)
    ? own.json.find(note => UUID.test(note?.id ?? ''))?.id : null;
  if (ownId) {
    await probe({ id: 'normal_owned_note', stage: 8, kind: 'normal_protected', path: `/api/notes/${ownId}`,
      request: 'GET /api/notes/:ownedId (본인)', expected: '본인 메모 한 건 HTTP 200', statuses: [200],
      headers: { Authorization: authorization, 'X-Resource-Id': `memo:${ownId.toLowerCase()}` },
      validate: json => json?.id?.toLowerCase() === ownId.toLowerCase() });
  } else skip('normal_owned_note', 8, 'normal_protected', 'GET /api/notes/:ownedId', '본인 메모 한 건 HTTP 200', prereq ?? 'owned_note_not_available');

  for (const args of [
    ['unregistered_device', 6, 'forbidden', '엔진의 미등록 기기 요청', '미등록 기기 거부', 'engine_feed_not_connected'],
    ['normal_step_up', 7, 'normal_protected', '엔진의 재확인 완료 요청', '재확인 뒤 자료 허용', 'engine_feed_not_connected'],
    ['compound_risk', 7, 'forbidden', '엔진의 복합 이상 요청', '추가 확인 전 자료 차단', 'engine_feed_not_connected'],
    ['other_owner', 8, 'forbidden', '다른 실계정으로 소유자 메모 조회', '타인 접근 거부', 'second_account_receipt_required'],
    ['normal_detection', 9, 'normal_protected', '엔진의 정상 조회 사건', '정상 사용자의 권한 유지', 'engine_feed_not_connected'],
    ['burst_revocation', 9, 'forbidden', '엔진의 조회 폭주 사건', '탐지와 실제 회수 확인', 'engine_feed_not_connected'],
    ['normal_recovery', 10, 'normal_protected', '엔진의 검증된 한 건 복구', '검증한 버전 복구와 감사 보존', 'engine_feed_not_connected'],
  ]) skip(...args);
  rows.sort((a, b) => a.stage - b.stage || a.id.localeCompare(b.id));
  const summary = summarizeMeasurements(rows);
  const protectedAllowed = rows.some(row => row.kind === 'normal_protected' && row.result === 'matched' && row.httpStatus === 200);
  const forbiddenRejected = rows.filter(row => row.kind === 'forbidden' && row.result === 'matched' && [401, 403].includes(row.httpStatus)).length;
  return { schema: 'aleph.api-measurements.v1', source: 'student_api_measurements', checkedAt: new Date().toISOString(),
    summary, rows, confirmation: { normalProtectedAllowed: protectedAllowed, forbiddenRejected,
      requiredPairMeasured: protectedAllowed && forbiddenRejected > 0,
      complete: protectedAllowed && forbiddenRejected > 0 && rows.every(row => row.result === 'matched') },
    finalAssault: { status: 'not_run', expectedCases: 41, measuredCases: null } };
}
