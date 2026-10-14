import { RULE_IDS } from './decider.mjs';
import { projectRecord, unavailableDomains } from '../public/ops-contract.js';

export async function readOperationsRecord() {
  // The current repository has no official operational-record reader or source contract.
  // Never substitute local exercises, static examples, or fresh probes for that source.
  throw new Error('operations_source_not_connected');
}

export function createOperationsHandler({ readRecord = readOperationsRecord } = {}) {
  return async function handler(req, res) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return res.status(405).json({ error: 'method_not_allowed' });
    }
    const sha = process.env.VERCEL_GIT_COMMIT_SHA;
    const commit = typeof sha === 'string' && /^[a-f0-9]{40}$/u.test(sha) ? sha : null;
    try {
      const raw = await readRecord();
      return res.status(200).json(projectRecord(raw, RULE_IDS, commit));
    } catch (error) {
      const code = readRecord === readOperationsRecord && error?.message === 'operations_source_not_connected'
        ? 'operations_source_not_connected' : 'operations_record_unavailable';
      // No fabricated empty summary; no source exceptions or private content are exposed.
      return res.status(503).json({ schema: 'aleph.ops.v1', status: 'unavailable', error: code,
        queriedAt: new Date().toISOString(), rules: { count: RULE_IDS.length, ids: [...RULE_IDS] },
        domains: unavailableDomains() });
    }
  };
}
