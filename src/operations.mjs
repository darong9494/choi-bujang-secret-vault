import { RULE_IDS } from './decider.mjs';

const keys = ['total', 'blocked', 'failed', 'notRun'];
const resultKey = { blocked: 'blocked', breached: 'failed', not_run: 'notRun' };
const categories = { decision: '운영 판정', detection: '운영 탐지', revocation: '운영 회수', recovery: '운영 복구' };
const isoTime = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)
  && Number.isFinite(Date.parse(value));

// Server-side adapter boundary only. Do not pass browser input, fixtures, or self-check records here.
// No production engine record reader is connected in this repository, so the API currently supplies null.
export function operationsSnapshot(record = null) {
  const sha = process.env.VERCEL_GIT_COMMIT_SHA;
  const commit = typeof sha === 'string' && /^[a-f0-9]{40}$/u.test(sha) ? sha : null;
  const unavailable = record === null;
  let items = [];
  let summary = Object.fromEntries(keys.map(key => [key, null]));
  if (!unavailable) {
    if (record.source !== 'operations' || !isoTime(record.checkedAt) || !Array.isArray(record.items)) {
      throw new Error('invalid_operations_record');
    }
    const ids = new Set();
    items = record.items.map(item => {
      if (typeof item.attackId !== 'string' || !/^[a-z0-9][a-z0-9_.-]{0,79}$/u.test(item.attackId)
          || ids.has(item.attackId) || !Object.hasOwn(categories, item.category)
          || !Object.hasOwn(resultKey, item.result) || !Number.isInteger(item.stage) || item.stage < 1 || item.stage > 12) {
        throw new Error('invalid_operation_item');
      }
      ids.add(item.attackId);
      const unrun = item.result === 'not_run';
      if (!unrun && (!Number.isInteger(item.httpStatus) || item.httpStatus < 100 || item.httpStatus > 599
          || !isoTime(item.checkedAt))) throw new Error('missing_operation_receipt');
      if (unrun && (item.httpStatus != null || item.checkedAt != null)) throw new Error('mixed_unrun_receipt');
      // Explicit allowlist: no note bodies, account/device identifiers, tokens, or arbitrary text.
      return { attackId: item.attackId, category: item.category, stage: item.stage, kind: 'operations',
        expected: categories[item.category], result: item.result, httpStatus: unrun ? null : item.httpStatus,
        checkedAt: unrun ? null : item.checkedAt, requestId: null,
        observed: unrun ? 'not_run' : `HTTP ${item.httpStatus}` };
    });
    summary = { total: items.length, blocked: 0, failed: 0, notRun: 0 };
    for (const item of items) summary[resultKey[item.result]]++;
    if (keys.some(key => record.summary?.[key] !== summary[key])) throw new Error('operations_summary_mismatch');
  }
  const reason = '운영 결과 조회 미연결 · 미실행';
  const domain = category => items.some(item => item.category === category && item.result !== 'not_run')
    ? { status: 'recorded', reason: '서버 전용 운영 기록 있음' } : { status: 'not_run', reason };
  return {
    schema: 'aleph.ops.v1', source: unavailable ? 'not_connected' : 'operations',
    status: unavailable ? 'not_run' : 'recorded', queriedAt: new Date().toISOString(),
    checkedAt: unavailable ? null : record.checkedAt, commit, summary, ...summary, items,
    rules: { count: RULE_IDS.length, ids: [...RULE_IDS] },
    decision: domain('decision'),
    detection: { ...domain('detection'), cases: items.filter(item => item.category === 'detection').map(item => item.attackId) },
    revocation: domain('revocation'),
    recovery: { status: 'not_run', available: false, valid: false, verifiedVersion: null,
      reason: '검증된 운영 복구 버전 미연결 · 미실행' },
  };
}
