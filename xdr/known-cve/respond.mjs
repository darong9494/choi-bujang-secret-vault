import { createHash, randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const RULES_PATH = fileURLToPath(new URL('../../artifacts/known-cve-deny-rules.json', import.meta.url));
const LOG_PATH = fileURLToPath(new URL('../alerts.log', import.meta.url));
const MAX_TTL = 3600000;
const writes = new Map();
const fingerprint = value => createHash('sha256').update(value).digest('hex');
const safeId = value => typeof value === 'string'
  && /^(?:[a-z]{1,12}-\d{1,12}|\d{1,16}(?:\.\d{1,16})?)$/u.test(value) ? value : null;

function timestamp(clock) {
  const now = clock();
  if (!Number.isSafeInteger(now) || !Number.isFinite(new Date(now).getTime())) {
    throw new Error('invalid_response_clock');
  }
  return now;
}

function attackSignatures(alert) {
  return ['url', 'useragent'].flatMap(field => {
    const value = alert?.data?.[field];
    if (typeof value !== 'string') return [];
    const result = decide({ data: { [field]: value } });
    return result.action === 'block' && result.confidence >= 0.85
      ? [{ field, fingerprint: fingerprint(value) }] : [];
  });
}

async function loadRules(path) {
  let text;
  try { text = await readFile(path, 'utf8'); }
  catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error('deny_rules_read_failed');
  }
  let state;
  try { state = JSON.parse(text); }
  catch { throw new Error('deny_rules_invalid'); }
  if (state?.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(state.rules)
      || !state.rules.every(rule => rule && rule.action === 'deny'
        && ['url', 'useragent'].includes(rule.field)
        && typeof rule.fingerprint === 'string' && /^[a-f0-9]{64}$/u.test(rule.fingerprint)
        && rule.id === `known_cve_${rule.field}_${rule.fingerprint}`
        && Number.isFinite(Date.parse(rule.createdAt)) && Number.isFinite(Date.parse(rule.expiresAt))
        && Date.parse(rule.expiresAt) > Date.parse(rule.createdAt)
        && Date.parse(rule.expiresAt) - Date.parse(rule.createdAt) <= MAX_TTL
        && Array.isArray(rule.evidenceAlertIds) && rule.evidenceAlertIds.length > 0
        && rule.evidenceAlertIds.every(id => safeId(id) !== null))) {
    throw new Error('deny_rules_invalid');
  }
  return state.rules.map(({ id, action, field, fingerprint, createdAt, expiresAt, evidenceAlertIds }) =>
    ({ id, action, field, fingerprint, createdAt, expiresAt, evidenceAlertIds }));
}

export async function getActiveDenials(alert, { rulesPath = RULES_PATH, clock = Date.now } = {}) {
  const now = timestamp(clock);
  const signatures = attackSignatures(alert);
  if (!signatures.length) return [];
  return (await loadRules(rulesPath)).filter(rule => Date.parse(rule.createdAt) <= now
    && now < Date.parse(rule.expiresAt)
    && signatures.some(s => s.field === rule.field && s.fingerprint === rule.fingerprint));
}

export function createResponder({ rulesPath = RULES_PATH, logPath = LOG_PATH,
  clock = Date.now, ttlMs = 600000 } = {}) {
  if (!Number.isInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TTL) throw new Error('invalid_rule_ttl');
  const path = resolve(rulesPath);
  return alert => {
    const pending = writes.get(path) ?? Promise.resolve();
    const next = pending.catch(() => {}).then(async () => {
      const now = timestamp(clock);
      const decision = decide(alert);
      const evidenceAlertId = safeId(alert?.id);
      let installed = 0;
      if (decision.action === 'block' && decision.confidence >= 0.85 && evidenceAlertId) {
        const signatures = attackSignatures(alert);
        if (signatures.length) {
          const rules = (await loadRules(path)).filter(rule => now < Date.parse(rule.expiresAt));
          for (const signature of signatures) {
            const id = `known_cve_${signature.field}_${signature.fingerprint}`;
            const existing = rules.find(rule => rule.id === id);
            if (existing) {
              if (!existing.evidenceAlertIds.includes(evidenceAlertId)) existing.evidenceAlertIds.push(evidenceAlertId);
            } else {
              rules.push({ id, action: 'deny', ...signature,
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
      }
      if (decision.action === 'block' || decision.action === 'alert') {
        await mkdir(dirname(resolve(logPath)), { recursive: true });
        await appendFile(logPath, `${JSON.stringify({ schema: 'aleph.xdr.alert.v1',
          at: new Date(now).toISOString(), evidenceAlertId, action: decision.action,
          confidence: decision.confidence, reason: decision.reason, installed,
          status: decision.action === 'block' && !evidenceAlertId ? 'missing_safe_alert_id' : 'processed' })}\n`,
        { mode: 0o600 });
      }
      return { decision, installed, evidenceAlertId };
    });
    writes.set(path, next);
    next.finally(() => { if (writes.get(path) === next) writes.delete(path); }).catch(() => {});
    return next;
  };
}

export const respond = createResponder();

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] !== '--fixture') throw new Error('fixture_option_required');
    const fixture = JSON.parse(await readFile(new URL('../fixtures/known-cve.json', import.meta.url), 'utf8'));
    if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'known-cve'
        || !Array.isArray(fixture.alerts)) throw new Error('invalid_fixture');
    const counts = { block: 0, alert: 0, record: 0 };
    for (const alert of fixture.alerts) counts[(await respond(alert)).decision.action] += 1;
    process.stdout.write(`${JSON.stringify({ source: 'local_fixture', counts })}\n`);
  } catch {
    process.stderr.write('경보 대응 실패: 실행 인자와 규칙·알림 저장 상태를 확인하세요.\n');
    process.exitCode = 1;
  }
}
