import { RULE_IDS } from './decider.mjs';
import { FIXTURE_CASES } from './ops-cases.mjs';

const TEST_ID = '00000000-0000-4000-8000-000000000001';
const KEYS = ['total', 'blocked', 'failed', 'notRun'];
const RESULT_KEY = Object.freeze({ blocked: 'blocked', breached: 'failed', not_run: 'notRun' });

export function summarizeItems(items) {
  const counts = { total: items.length, blocked: 0, failed: 0, notRun: 0 };
  for (const item of items) {
    if (!Object.hasOwn(RESULT_KEY, item.result)) throw new Error('invalid_check_result');
    counts[RESULT_KEY[item.result]]++;
  }
  return counts;
}

export function submissionAttempts(items) {
  return items.map(({ attackId, stage, expected, observed, result }) => ({ attackId, stage, expected, observed, result }));
}

export async function collectOpsRecord(config) {
  const base = new URL(config.publicAppUrl);
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash
      || base.pathname !== '/' || !base.hostname.endsWith('.vercel.app')) throw new Error('invalid_app_url');
  const definitions = [
    ['existing_vault_screen', 1, '/', '공개 자료실 화면 HTTP 200', 200],
    ['anonymous_notes_read', 3, '/api/notes', '비로그인 메모 읽기 거부', 401],
    ['forged_login_token', 3, '/api/notes', '위조 토큰 거부', 401, { Authorization: 'Bearer a.b.c' }],
    ['query_identity_spoof', 4, `/api/notes?user_id=${TEST_ID}`, '쿼리 신원 위조 거부', 401],
    ['anonymous_note_restore', 10, `/api/restore/${TEST_ID}`, '비로그인 복원 경로 거부', [401, 403, 404]],
    ['anonymous_device_approval', 11, '/api/device/status', '비로그인 기기 승인 거부', 401],
    ...FIXTURE_CASES.map(([id, stage, expected]) => [id, stage, `/api/checks?case=${id}`, expected, 200, {}, true]),
  ];
  const items = await Promise.all(definitions.map(async ([attackId, stage, path, expected, status, headers = {}, fixture = false]) => {
    const item = { attackId, stage, expected, request: `GET ${path}`, kind: fixture ? 'fixture_api' : 'live_api' };
    try {
      const response = await fetch(new URL(path, base), {
        method: 'GET', headers: { Accept: 'application/json', ...headers }, redirect: 'manual',
        signal: AbortSignal.timeout(5000), alephEvidence: { caseId: attackId, requestKey: 'read' },
      });
      // Inspect in memory, then discard the body. Never place it in records or logs.
      const body = await response.text();
      let data;
      try { data = JSON.parse(body); } catch { data = null; }
      const exposesNotes = /"(?:content|body)"\s*:/u.test(body);
      const statusMatches = (Array.isArray(status) ? status : [status]).includes(response.status);
      const ready = fixture && typeof data?.ready === 'boolean' ? data.ready : null;
      const matches = statusMatches && (fixture ? data?.source === 'student_fixture' && ready === true
        : attackId === 'existing_vault_screen' || !exposesNotes);
      const rawId = response.headers.get('x-vercel-id');
      const requestId = typeof rawId === 'string' && /^[a-zA-Z0-9:._-]{1,100}$/u.test(rawId) ? rawId : null;
      let outcome = null;
      if (fixture && ['allow', 'deny', 'step_up'].includes(data?.decision)) outcome = { decision: data.decision };
      if (fixture && ['observe', 'propose_revocation'].includes(data?.action)
          && Number.isInteger(data.eventCount) && data.eventCount >= 0 && data.eventCount <= 121) {
        outcome = { action: data.action, eventCount: data.eventCount };
      }
      return { ...item, checkedAt: new Date().toISOString(), httpStatus: response.status, requestId,
        outcome,
        observed: `HTTP ${response.status}; bodyBytes=${Buffer.byteLength(body)}`
          + (ready !== null ? `; jsonReady=${ready}` : ''),
        result: matches ? 'blocked' : 'breached' };
    } catch {
      return { ...item, checkedAt: new Date().toISOString(), httpStatus: null, requestId: null,
        observed: 'network_error', result: 'not_run' };
    }
  }));
  for (const [attackId, stage, expected] of [
    ['registered_device_read_live', 11, '등록된 실기기 메모 읽기'],
    ['other_owner_read_live', 8, '다른 실계정 메모 접근 거부'],
    ['engine_revocation_live', 9, '운영 엔진의 실제 권한 회수'],
    ['engine_restore_live', 10, '운영 엔진의 검증 사본 복원'],
    ['engine_audit_live', 10, '운영 엔진의 감사 기록 확인'],
  ]) items.push({ attackId, stage, expected, request: null, kind: 'not_run', checkedAt: null,
    httpStatus: null, requestId: null, observed: 'not_run', result: 'not_run' });
  const summary = summarizeItems(items);
  const sha = process.env.VERCEL_GIT_COMMIT_SHA;
  const commit = typeof sha === 'string' && /^[a-f0-9]{40}$/u.test(sha) ? sha : null;
  const record = {
    schema: 'aleph.ops.v1', checkedAt: new Date().toISOString(), commit,
    summary, ...summary, items,
    rules: { count: RULE_IDS.length, ids: [...RULE_IDS] },
    detection: { source: 'student_fixture', liveStatus: 'not_run',
      cases: items.filter(item => item.attackId.endsWith('_detection')).map(item => item.attackId) },
    revocation: { status: 'not_run', reason: '운영 엔진의 실제 회수 결과 미연결' },
    recovery: { status: 'not_run', available: false, valid: false, verifiedVersion: null,
      deploymentVersion: commit, reason: '운영 엔진의 검증 사본·복구 버전·감사 기록 미연결' },
  };
  if (!KEYS.every(key => record[key] === record.summary[key])) throw new Error('invalid_summary');
  return record;
}
