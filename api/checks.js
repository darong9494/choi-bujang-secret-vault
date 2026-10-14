import { readFileSync } from 'node:fs';
import { runRuleCheck } from '../src/rule-check.mjs';
import { collectOpsSnapshot } from '../src/ops-snapshot.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));

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
    const snapshot = await collectOpsSnapshot(config);
    const totals = snapshot.summary;
    const checks = snapshot.items.map(item => ({ ...item, id: item.attackId, title: item.expected }));
    return res.status(200).json({
      schema: 'aleph.ops.snapshot.v1', checkedAt: snapshot.checkedAt,
      commit: snapshot.commit, recordedCommit: snapshot.commit,
      ...totals, totals, checks, policyRules: snapshot.rules.ids,
      detection: '학생 코드의 가상 사건 연습; 실제 권한 회수는 미실행',
      restore: '9단계 통과 커밋은 복구 기준 후보; 엔진 복원은 미실행',
      note: '이번 조회에서 실제 요청한 학생 자기 점검 결과입니다. 가상 연습과 미실행 항목을 구분하며 운영 심판의 시험 결과는 포함하지 않습니다.',
    });
  } catch {
    return res.status(503).json({ error: 'checks_unavailable' });
  }
}
