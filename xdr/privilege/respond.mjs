import { createHash, randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const DEFAULT_RULES = fileURLToPath(new URL('../../artifacts/privilege-deny-rules.json', import.meta.url));
const DEFAULT_LOG = fileURLToPath(new URL('../alerts.log', import.meta.url));
const MAX_TTL = 3600000;
const queues = new Map();
const safeId = value => typeof value === 'string'
  && /^(?:[a-z]{1,16}-\d{1,12}|\d{1,16}(?:\.\d{1,16})?)$/u.test(value) ? value : null;

function scopeHash(value) {
  if (!value || typeof value.subjectId !== 'string' || !value.subjectId.trim()
      || !['classId', 'projectId'].every(key => typeof value[key] === 'string' && value[key].trim())) return null;
  return createHash('sha256').update(JSON.stringify([value.classId, value.projectId, value.subjectId])).digest('hex');
}

function time(clock) {
  const now = clock();
  if (!Number.isSafeInteger(now) || !Number.isFinite(new Date(now).getTime())) throw new Error('invalid_response_clock');
  return now;
}

async function readRules(path) {
  let raw;
  try { raw = await readFile(path, 'utf8'); }
  catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error('privilege_rules_read_failed');
  }
  let state;
  try { state = JSON.parse(raw); }
  catch { throw new Error('privilege_rules_invalid'); }
  if (state?.schema !== 'aleph.xdr.privilege-denials.v1' || !Array.isArray(state.rules)
      || !state.rules.every(rule => rule && rule.action === 'deny'
        && typeof rule.scopeHash === 'string' && /^[a-f0-9]{64}$/u.test(rule.scopeHash)
        && rule.id === `privilege_${rule.scopeHash}`
        && Number.isFinite(Date.parse(rule.createdAt)) && Number.isFinite(Date.parse(rule.expiresAt))
        && Date.parse(rule.expiresAt) > Date.parse(rule.createdAt)
        && Date.parse(rule.expiresAt) - Date.parse(rule.createdAt) <= MAX_TTL
        && Array.isArray(rule.evidenceAlertIds) && rule.evidenceAlertIds.length > 0
        && rule.evidenceAlertIds.every(id => safeId(id) !== null))) {
    throw new Error('privilege_rules_invalid');
  }
  return state.rules.map(({ id, action, scopeHash, createdAt, expiresAt, evidenceAlertIds }) =>
    ({ id, action, scopeHash, createdAt, expiresAt, evidenceAlertIds }));
}

export async function getActiveDenials(request, { rulesPath = DEFAULT_RULES, clock = Date.now } = {}) {
  const now = time(clock);
  const target = scopeHash(request);
  if (!target) return [];
  return (await readRules(rulesPath)).filter(rule => rule.scopeHash === target
    && Date.parse(rule.createdAt) <= now && now < Date.parse(rule.expiresAt));
}

export function createResponder({ rulesPath = DEFAULT_RULES, logPath = DEFAULT_LOG,
  clock = Date.now, ttlMs = 600000 } = {}) {
  if (!Number.isInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TTL) throw new Error('invalid_rule_ttl');
  const path = resolve(rulesPath);
  return (alert, { binding } = {}) => {
    const prior = queues.get(path) ?? Promise.resolve();
    const next = prior.catch(() => {}).then(async () => {
      const now = time(clock);
      const decision = decide(alert); // Ignore caller-supplied action/confidence claims.
      const alertId = safeId(alert?.id);
      const target = scopeHash(binding);
      const bound = target && typeof binding.agentName === 'string' && binding.agentName.length > 0
        && binding.agentName === alert?.agent?.name
        && typeof binding.sourceAccount === 'string' && binding.sourceAccount.trim().length > 0
        && typeof alert?.data?.srcuser === 'string'
        && binding.sourceAccount.trim().toLowerCase() === alert.data.srcuser.trim().toLowerCase();
      const at = typeof alert?.timestamp === 'string' ? Date.parse(alert.timestamp) : NaN;
      let installed = 0;
      let ruleId = null;
      let status = 'not_required';
      if (decision.action === 'block' && decision.confidence >= 0.85) {
        status = !alertId ? 'missing_safe_alert_id' : !bound ? 'binding_unverified'
          : !Number.isFinite(at) || at > now || now - at >= ttlMs ? 'stale_or_invalid_event' : 'eligible';
        if (status === 'eligible') {
          const rules = (await readRules(path)).filter(rule => now < Date.parse(rule.expiresAt));
          ruleId = `privilege_${target}`;
          const existing = rules.find(rule => rule.id === ruleId);
          if (existing) {
            if (!existing.evidenceAlertIds.includes(alertId)) existing.evidenceAlertIds.push(alertId);
            status = 'rule_already_active'; // Replays do not prolong the expiry.
          } else {
            rules.push({ id: ruleId, action: 'deny', scopeHash: target,
              createdAt: new Date(at).toISOString(), expiresAt: new Date(at + ttlMs).toISOString(),
              evidenceAlertIds: [alertId] });
            installed = 1;
            status = 'rule_created';
          }
          await mkdir(dirname(path), { recursive: true });
          const temporary = `${path}.${randomUUID()}.tmp`;
          await writeFile(temporary, `${JSON.stringify({ schema: 'aleph.xdr.privilege-denials.v1', rules }, null, 2)}\n`,
            { mode: 0o600 });
          await rename(temporary, path);
        }
      }
      if (decision.action === 'block' || decision.action === 'alert') {
        await mkdir(dirname(resolve(logPath)), { recursive: true });
        await appendFile(logPath, `${JSON.stringify({ schema: 'aleph.xdr.alert.v1', moduleKey: 'privilege',
          at: new Date(now).toISOString(), evidenceAlertId: alertId,
          action: decision.action, confidence: decision.confidence, reason: decision.reason, installed, status })}\n`,
        { mode: 0o600 });
      }
      return { decision, installed, ruleId, status };
    });
    queues.set(path, next);
    next.finally(() => { if (queues.get(path) === next) queues.delete(path); }).catch(() => {});
    return next;
  };
}

export const respond = createResponder();
