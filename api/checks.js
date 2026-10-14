import ops from './ops.js';
import { runOpsCase } from '../src/ops-cases.mjs';

export default async function handler(req, res) {
  if (req.method !== 'GET' || req.query?.case === undefined) return ops(req, res);
  res.setHeader('Cache-Control', 'no-store');
  const result = typeof req.query.case === 'string' ? await runOpsCase(req.query.case) : null;
  return result ? res.status(200).json(result) : res.status(400).json({ error: 'unknown_check' });
}
