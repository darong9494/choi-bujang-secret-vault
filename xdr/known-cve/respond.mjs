import { createHash, randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const DEFAULT_RULES = fileURLToPath(new URL('../../artifacts/known-cve-deny-rules.json', import.meta.url));
const DEFAULT_LOG = fileURLToPath(new URL('../alerts.log', import.meta.url));
const MAX_TTL = 60 * 60 * 1000;
const queues = new Map();
const digest = value => createHash('sha256').update(value).digest('hex');
const safeAlertId = value => typeof value === 'string'
  && /^(?:[a-z]{1,12}-\d{1,12}|\d{1,16}(?:\.\d{1,16})?)$/u.test(value) ? value : null;

function clockTime(clock) {
  const now = clock();
  if (!Number.isSafeInteger(now) || !Number.isFinite(new Date(now).getTime())) {
    throw new Error('invalid_response_clock');
  }
  return now;
}

function signatures(alert) {
  const result = [];
  for (const field of ['useragent', 'url']) {
    const value = alert?.data?.[field];
    // Independently recheck actual input: labels, IPs and accounts never define a denial.
    if (typeof value === 'string' && decide({ data: { [field]: value } }).action === 'block') {
      result.push({ field, fingerprint: digest(value) });
    }
  }
  return result;
}

async function readRules(path) {
  let raw;
  try { raw = await readFile(path, 'utf8'); }
  catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error('deny_rules_read_failed');
  }
  let state;
  try { state = JSON.parse(raw); }
  catch { throw new Error('deny_rules_invalid'); }
  if (state?.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(state.rules)
      || !state.rules.every(rule => rule && rule.action === 'deny'
        && ['url', 'useragent'].includes(rule.field)
        && /^[a-f0-9]{64}$/u.test(rule.fingerprint)
        && rule.id === `known_cve_${rule.field}_${rule.fingerprint}`
        && Number.isFinite(Date.parse(rule.createdAt))
        && Number.isFinite(Date.parse(rule.expiresAt))
        && Date.parse(rule.expiresAt) > Date.parse(rule.createdAt)
        && Date.parse(rule.expiresAt) - Date.parse(rule.createdAt) <= MAX_TTL
        && Array.isArray(rule.evidenceAlertIds) && rule.evidenceAlertIds.length > 0
        && rule.evidenceAlertIds.every(id => safeAlertId(id) !== null))) {
    throw new Error('deny_rules_invalid');
  }
  // Project fields so unexpected stored data never reaches callers or rewritten files.
  return state.rules.map(({ id, action, field, fingerprint, createdAt, expiresAt, evidenceAlertIds }) =>
    ({ id, action, field, fingerprint, createdAt, expiresAt, evidenceAlertIds }));
}

export async function getActiveDenials(alert, { rulesPath = DEFAULT_RULES, clock = Date.now } = {}) {
  const now = clockTime(clock);
  const candidates = signatures(alert);
  if (candidates.length === 0) return [];
  const rules = await readRules(rulesPath);
  return rules.filter(rule => Date.parse(rule.createdAt) <= now && now < Date.parse(rule.expiresAt)
    && candidates.some(candidate => candidate.field === rule.field && candidate.fingerprint === rule.fingerprint));
}

export function createResponder({ rulesPath = DEFAULT_RULES, logPath = DEFAULT_LOG,
  clock = Date.now, ttlMs = 10 * 60 * 1000 } = {}) {
  if (!Number.isInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TTL) throw new Error('invalid_deny_rule_ttl');
  const path = resolve(rulesPath);
  return alert => {
    const previous = queues.get(path) ?? Promise.resolve();
    const next = previous.catch(() => {}).then(async () => {
      const now = clockTime(clock);
      const decision = decide(alert);
      const evidenceAlertId = safeAlertId(alert?.id);
      let installed = 0;
      if (decision.action === 'block' && decision.confidence >= 0.85 && evidenceAlertId) {
        const rules = (await readRules(path)).filter(rule => now < Date.parse(rule.expiresAt));
        for (const candidate of signatures(alert)) {
          const id = `known_cve_${candidate.field}_${candidate.fingerprint}`;
          const existing = rules.find(rule => rule.id === id);
          if (existing) {
            // Replaying the same event neither duplicates rules nor prolongs a ban.
            if (!existing.evidenceAlertIds.includes(evidenceAlertId)) {
              existing.evidenceAlertIds.push(evidenceAlertId);
            }
          } else {
            rules.push({ id, action: 'deny', ...candidate,
              createdAt: new Date(now).toISOString(), expiresAt: new Date(now + ttlMs).toISOString(),
              evidenceAlertIds: [evidenceAlertId] });
            installed += 1;
          }
        }
        await mkdir(dirname(path), { recursive: true });
        const temporary = `${path}.${randomUUID()}.tmp`;
        await writeFile(temporary, `${JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules }, null, 2)}\n`,
          { mode: 0o600 });
        await rename(temporary, path);
      }
      if (decision.action === 'block' || decision.action === 'alert') {
        await mkdir(dirname(resolve(logPath)), { recursive: true });
        // Reasons come from the pure module; never append raw alert fields or caller results.
        await appendFile(logPath, `${JSON.stringify({ at: new Date(now).toISOString(),
          evidenceAlertId, ...decision, installed,
          status: decision.action === 'block' && !evidenceAlertId ? 'missing_safe_alert_id' : 'processed' })}\n`,
        { mode: 0o600 });
      }
      return { decision, installed, evidenceAlertId };
    });
    queues.set(path, next);
    next.finally(() => { if (queues.get(path) === next) queues.delete(path); }).catch(() => {});
    return next;
  };
}

export const respond = createResponder();

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] !== '--fixture') throw new Error('fixture_option_required');
    const fixture = JSON.parse(await readFile(new URL('../fixtures/known-cve.json', import.meta.url), 'utf8'));
    if (fixture?.moduleKey !== 'known-cve' || !Array.isArray(fixture.alerts)) throw new Error('invalid_fixture');
    const counts = { block: 0, alert: 0, record: 0 };
    for (const alert of fixture.alerts) counts[(await respond(alert)).decision.action] += 1;
    process.stdout.write(`${JSON.stringify({ source: 'local_fixture', counts })}\n`);
  } catch {
    process.stderr.write('경보 대응 처리 실패: 규칙·로그 저장 상태와 실행 인자를 확인하세요.\n');
    process.exitCode = 1;
  }
}
