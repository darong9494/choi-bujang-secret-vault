import { runAttackChecks } from './attack-check.mjs';
import { RULE_IDS } from './decider.mjs';

const fixtureIds = new Set([
  'registered_device_read', 'unregistered_device_read',
  'composite_risk_step_up', 'engine_verified_step_up',
  'normal_read_detection', 'unusual_network_burst_revocation_proposal',
]);

// Both APIs publish the same record shape; no saved receipt or assumed result is used.
export async function collectOpsSnapshot(config) {
  const attempts = await runAttackChecks(config);
  const checkedAt = new Date().toISOString();
  const deploymentCommit = process.env.VERCEL_GIT_COMMIT_SHA;
  const commit = typeof deploymentCommit === 'string' && /^[a-f0-9]{40}$/u.test(deploymentCommit)
    ? deploymentCommit : null;
  const items = attempts.map(attempt => {
    const status = /^HTTP (\d{3})(?:;|$)/u.exec(attempt.observed);
    const id = /; requestId=([a-zA-Z0-9:._-]{1,100})(?:;|$)/u.exec(attempt.observed);
    const source = attempt.observed === 'network_error' ? '요청 후 응답 확인 실패'
      : attempt.result === 'not_run' ? '요청 미실행'
      : fixtureIds.has(attempt.attackId) ? '학생 판정기·탐지 가상 연습' : '배포 API 실측';
    return { ...attempt, source,
      kind: attempt.result === 'not_run' ? 'not_run' : 'live_api',
      httpStatus: status ? Number(status[1]) : null, requestId: id?.[1] ?? null };
  });
  const count = result => items.filter(item => item.result === result).length;
  return {
    schema: 'aleph.ops.v1', checkedAt, commit,
    rules: { count: RULE_IDS.length, ids: [...RULE_IDS] },
    recovery: { available: false, valid: false, reason: '제공 엔진의 검증 사본·복원 기록 미연결' },
    summary: { total: items.length, blocked: count('blocked'), failed: count('breached'), notRun: count('not_run') },
    items,
  };
}
