export const CATEGORIES = Object.freeze(['decision', 'detection', 'revocation', 'recovery']);
const OUTCOMES = {
  decision: ['allow', 'deny', 'step_up'], detection: ['observe', 'propose_revocation'],
  revocation: ['revoked', 'failed'], recovery: ['restored', 'failed'],
};
const isTime = value => typeof value === 'string'
  && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)
  && Number.isFinite(Date.parse(value));

export function countRecords(records) {
  const summary = { total: records.length, recorded: 0, notRun: 0 };
  for (const row of records) {
    if (!CATEGORIES.includes(row.category) || !['recorded', 'not_run'].includes(row.status)) throw new Error('invalid_record');
    if (row.status === 'not_run') {
      if (row.outcome !== null || row.at !== null || row.policyRevision !== null) throw new Error('unrun_has_result');
      summary.notRun++;
    } else {
      if (!OUTCOMES[row.category].includes(row.outcome) || !isTime(row.at)) throw new Error('missing_actual_result');
      summary.recorded++;
    }
  }
  return summary;
}

// Application-owned view model, not a claim about the operator's undocumented API.
// Called only with a server-side reader result, never with browser request data.
export function projectRecord(raw, rules, commit = null) {
  if (raw?.schema !== 'aleph.operations-record.v1' || raw.source !== 'server_record'
      || !isTime(raw.checkedAt) || !Array.isArray(raw.records) || raw.records.length > 1000) {
    throw new Error('invalid_source_record');
  }
  const records = raw.records.map((row, index) => {
    if (!row || !CATEGORIES.includes(row.category) || !['recorded', 'not_run'].includes(row.status)) throw new Error('invalid_record');
    const unrun = row.status === 'not_run';
    if (unrun && (row.outcome != null || row.at != null || row.policyRevision != null)) throw new Error('unrun_has_result');
    if (row.policyRevision != null && (!Number.isSafeInteger(row.policyRevision) || row.policyRevision < 0)) throw new Error('invalid_revision');
    const ruleIds = row.ruleIds ?? [];
    if (!Array.isArray(ruleIds) || ruleIds.some(id => !rules.includes(id))) throw new Error('unknown_rule');
    // Deliberate whitelist: omit memo bodies, account/device IDs, tokens and arbitrary descriptions.
    return { number: index + 1, category: row.category, status: row.status,
      outcome: unrun ? null : row.outcome, at: unrun ? null : row.at,
      policyRevision: row.policyRevision ?? null, ruleIds: [...new Set(ruleIds)] };
  });
  const counted = countRecords(records);
  if (Object.keys(counted).some(key => raw.summary?.[key] !== counted[key])) throw new Error('summary_mismatch');
  return { schema: 'aleph.ops.v1', status: 'recorded', source: 'server_record',
    checkedAt: raw.checkedAt, commit, rules: { count: rules.length, ids: [...rules] },
    summary: { total: raw.summary.total, recorded: raw.summary.recorded, notRun: raw.summary.notRun }, records };
}

export function validateSnapshot(data) {
  if (data?.schema !== 'aleph.ops.v1' || data.status !== 'recorded' || data.source !== 'server_record'
      || !isTime(data.checkedAt) || !Array.isArray(data.records) || !Array.isArray(data.rules?.ids)
      || data.rules.count !== data.rules.ids.length) throw new Error('invalid_snapshot');
  const counted = countRecords(data.records);
  if (Object.keys(counted).some(key => data.summary?.[key] !== counted[key])) throw new Error('summary_mismatch');
  return data;
}
