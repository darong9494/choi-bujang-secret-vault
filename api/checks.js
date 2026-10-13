import { readFileSync } from 'node:fs';
import { runRuleCheck } from '../src/rule-check.mjs';
import { RULE_IDS } from '../src/decider.mjs';

const record = JSON.parse(readFileSync(new URL('../src/ops-record.json', import.meta.url), 'utf8'));
const fixtureIds = new Set([
  'registered_device_read', 'unregistered_device_read',
  'composite_risk_step_up', 'engine_verified_step_up',
  'normal_read_detection', 'unusual_network_burst_revocation_proposal',
]);

function summarize(attempts) {
  const checks = attempts.map(attempt => {
    const status = /^HTTP (\d{3})(?:;|$)/u.exec(attempt.observed);
    const id = /; requestId=([a-zA-Z0-9:._-]{1,100})(?:;|$)/u.exec(attempt.observed);
    const source = attempt.observed === 'network_error' ? '요청 후 응답 확인 실패'
      : attempt.result === 'not_run' ? '요청 미실행'
      : fixtureIds.has(attempt.attackId) ? '학생 판정기·탐지 가상 연습' : '배포 API 실측';
    return { id: attempt.attackId, stage: attempt.stage, title: attempt.expected,
      source, result: attempt.result, observed: attempt.observed,
      httpStatus: status ? Number(status[1]) : null, requestId: id?.[1] ?? null };
  });
  return { checks, totals: {
    total: checks.length,
    blocked: checks.filter(check => check.result === 'blocked').length,
    failed: checks.filter(check => check.result === 'breached').length,
    notRun: checks.filter(check => check.result === 'not_run').length,
  } };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  if (req.query?.case !== undefined) {
    const result = await runRuleCheck(req.query.case);
    return result ? res.status(200).json(result) : res.status(400).json({ error: 'unknown_check' });
  }
  try {
    if (record.schema !== 'aleph.student-check-record.v1' || !Array.isArray(record.attackAttempts)) {
      throw new Error('invalid_record');
    }
    const { checks, totals } = summarize(record.attackAttempts);
    const deploymentCommit = process.env.VERCEL_GIT_COMMIT_SHA;
    const currentCommit = typeof deploymentCommit === 'string' && /^[a-f0-9]{40}$/u.test(deploymentCommit)
      ? deploymentCommit : null;
    return res.status(200).json({
      schema: 'aleph.ops.snapshot.v1', checkedAt: record.checkedAt,
      commit: currentCommit, recordedCommit: record.commit,
      totals, checks, policyRules: [...RULE_IDS],
      detection: '학생 코드의 가상 사건 연습; 실제 권한 회수는 미실행',
      restore: '9단계 통과 커밋은 복구 기준 후보; 엔진 복원은 미실행',
      note: '저장된 학생 자기 점검 기록입니다. 점검 대상 커밋은 별도로 표시합니다. 운영 심판의 41종 시험 결과는 이 수치에 포함하지 않습니다.',
    });
  } catch {
    return res.status(503).json({ error: 'checks_unavailable' });
  }
}
