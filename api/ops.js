import { operationsSnapshot } from '../src/operations.mjs';

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  try {
    return res.status(200).json(operationsSnapshot());
  } catch {
    return res.status(503).json({ error: 'ops_unavailable' });
  }
}
