import { readFileSync } from 'node:fs';
import { collectOpsRecord } from '../src/ops-record.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  try {
    return res.status(200).json(await collectOpsRecord(config));
  } catch {
    return res.status(503).json({ error: 'ops_unavailable' });
  }
}
