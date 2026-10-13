import { readFileSync } from 'node:fs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { RULE_IDS } from '../src/decider.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const liveChecks = Object.freeze({
  existing_vault_screen: ['자료실 화면 응답', [200]],
  anonymous_notes_read: ['비로그인 메모 거부', [401]],
  anonymous_note_restore: ['비로그인 복원 경로 응답', [401, 403, 404]],
  anonymous_device_approval: ['비로그인 기기 승인 거부', [401]],
  forged_login_token: ['위조 토큰 거부', [401]],
  query_identity_spoof: ['쿼리 신원 위조 거부', [401]],
});

const pendingChecks = Object.freeze([
  ['registered_device_read_live', '등록된 기기의 메모 읽기', '등록된 실기기 세션 없음'],
  ['other_owner_read_live', '다른 사용자 메모 접근 거부', '두 실계정 요청 미실행'],
  ['engine_revocation_live', '탐지 뒤 실제 권한 회수', '운영 엔진 회수 기록 미연결'],
  ['engine_restore_live', '검증 사본 한 건 복원', '운영 엔진 백업·복원 기록 미연결'],
  ['engine_audit_live', '복원 감사 이력 보존', '운영 엔진 감사 기록 미연결'],
]);

function summarize(attempts) {
  const checks = attempts.map(attempt => {
    const live = liveChecks[attempt.attackId];
    if (!live) return {
      id: attempt.attackId, title: attempt.expected, source: '가상 연습',
      result: attempt.observed.startsWith('로컬 가상') ? 'simulated' : 'not_run',
      httpStatus: null, requestId: null,
    };
    const status = /^실제 GET \S+ HTTP (\d{3});/u.exec(attempt.observed);
    const requestId = /; x-vercel-id=([a-zA-Z0-9:._-]{1,100});/u.exec(attempt.observed);
    const httpStatus = status ? Number(status[1]) : null;
    return {
      id: attempt.attackId, title: live[0], source: '배포 API 실측',
      result: httpStatus === null ? 'not_run' : live[1].includes(httpStatus) ? 'passed' : 'failed',
      httpStatus, requestId: requestId?.[1] ?? null,
    };
  });
  for (const [id, title, reason] of pendingChecks) {
    checks.push({ id, title, source: reason, result: 'not_run', httpStatus: null, requestId: null });
  }
  const totals = { passed: 0, failed: 0, notRun: 0, simulated: 0 };
  for (const check of checks) {
    if (check.result === 'passed') totals.passed++;
    else if (check.result === 'failed') totals.failed++;
    else if (check.result === 'simulated') totals.simulated++;
    else totals.notRun++;
  }
  return { checks, totals };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  try {
    const attempts = await runAttackChecks(config);
    const { checks, totals } = summarize(attempts);
    const commit = process.env.VERCEL_GIT_COMMIT_SHA;
    return res.status(200).json({
      schema: 'aleph.ops.snapshot.v1', checkedAt: new Date().toISOString(),
      commit: typeof commit === 'string' && /^[a-f0-9]{40}$/u.test(commit) ? commit : null,
      totals, checks, policyRules: [...RULE_IDS],
      detection: '가상 사건 연습만 실행; 운영 회수 미확인',
      restore: '9단계 통과 커밋을 기준 후보로 기록; 운영 복원 미확인',
      note: '서버 자체 점검입니다. 운영 심판 판정과 엔진 감사 기록이 아닙니다.',
    });
  } catch {
    return res.status(503).json({ error: 'checks_unavailable' });
  }
}
