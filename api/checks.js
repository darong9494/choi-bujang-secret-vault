import { readFileSync } from 'node:fs';
import { collectOpsRecord } from '../src/ops-record.mjs';
import { runOpsCase } from '../src/ops-cases.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  if (req.query?.case === undefined) {
    try {
      const record = await collectOpsRecord(config);
      return res.status(200).json({ ...record, schema: 'aleph.student-checks.v1', source: 'student_self_check' });
    } catch {
      return res.status(503).json({ error: 'checks_unavailable' });
    }
  }
  const result = typeof req.query.case === 'string' ? await runOpsCase(req.query.case) : null;
  return result ? res.status(200).json(result) : res.status(400).json({ error: 'unknown_check' });
}
