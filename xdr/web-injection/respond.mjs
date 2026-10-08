import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decide } from './decide.mjs';

const moduleDir = dirname(fileURLToPath(import.meta.url));
const defaultRoot = resolve(moduleDir, '..', '..');
const RULE_SCHEMA = 'aleph.xdr.deny-rules.v1';
const RULE_ID = 'web_injection_query_deny';
const RULE_TTL_MS = 15 * 60 * 1000;

function requestFingerprint(alert) {
  const rawUrl = alert?.data?.url;
  if (typeof rawUrl !== 'string' || !rawUrl) return null;

  const urlWithoutFragment = rawUrl.split('#', 1)[0];
  const queryStart = urlWithoutFragment.indexOf('?');
  if (queryStart < 0) return null;

  const rawQuery = urlWithoutFragment.slice(queryStart + 1);
  if (!rawQuery) return null;

  let path;
  try {
    path = new URL(urlWithoutFragment.slice(0, queryStart), 'https://wazuh-fixture.invalid').pathname;
  } catch {
    return null;
  }
  if (!path.startsWith('/')) return null;

  return {
    path,
    queryLength: rawQuery.length,
    querySha256: createHash('sha256').update(rawQuery, 'utf8').digest('hex'),
  };
}

function fingerprintKey(rule) {
  return `${rule.path}\n${rule.queryLength}\n${rule.querySha256}`;
}

function isValidRule(rule, nowMs) {
  return Boolean(rule)
    && rule.ruleId === RULE_ID
    && typeof rule.path === 'string'
    && rule.path.startsWith('/')
    && Number.isSafeInteger(rule.queryLength)
    && rule.queryLength > 0
    && typeof rule.querySha256 === 'string'
    && /^[a-f0-9]{64}$/i.test(rule.querySha256)
    && Array.isArray(rule.evidenceAlertIds)
    && rule.evidenceAlertIds.length > 0
    && Number.isFinite(Date.parse(rule.expiresAt))
    && Date.parse(rule.expiresAt) > nowMs;
}

async function readActiveRules(rulesPath, nowMs) {
  try {
    const stored = JSON.parse(await readFile(rulesPath, 'utf8'));
    if (stored?.schema !== RULE_SCHEMA || !Array.isArray(stored.rules)) {
      throw new TypeError('Temporary deny rule file has an invalid format.');
    }
    return stored.rules.filter((rule) => isValidRule(rule, nowMs));
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

export async function respond({ root = defaultRoot, now = new Date() } = {}) {
  const nowDate = now instanceof Date ? now : new Date(now);
  const nowMs = nowDate.getTime();
  if (!Number.isFinite(nowMs)) throw new TypeError('A valid response time is required.');

  const xdrRoot = join(root, 'xdr');
  const fixture = JSON.parse(await readFile(join(xdrRoot, 'fixtures', 'web-injection.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'web-injection'
      || !Array.isArray(fixture.alerts)) {
    throw new TypeError('Web injection alert fixture has an invalid format.');
  }

  const evaluated = fixture.alerts.map((alert) => ({
    alert,
    result: decide(alert),
    fingerprint: requestFingerprint(alert),
  }));
  const protectedFingerprints = new Set(evaluated
    .filter(({ result }) => result.action !== 'block')
    .map(({ fingerprint }) => fingerprint && fingerprintKey(fingerprint))
    .filter(Boolean));

  const expiresAt = new Date(nowMs + RULE_TTL_MS).toISOString();
  const newRules = new Map();
  for (const { alert, result, fingerprint } of evaluated) {
    if (result.action !== 'block' || result.confidence < 0.85 || !fingerprint) continue;
    const key = fingerprintKey(fingerprint);
    if (protectedFingerprints.has(key)) continue;

    const alertId = typeof alert?.id === 'string' ? alert.id : '';
    if (!alertId) continue;
    const previous = newRules.get(key);
    if (previous) {
      previous.evidenceAlertIds.push(alertId);
    } else {
      newRules.set(key, {
        ruleId: RULE_ID,
        ...fingerprint,
        expiresAt,
        evidenceAlertIds: [alertId],
      });
    }
  }

  const rulesPath = join(xdrRoot, 'web-injection', 'deny-rules.json');
  const activeRules = await readActiveRules(rulesPath, nowMs);
  const mergedRules = new Map(activeRules
    .filter((rule) => !protectedFingerprints.has(fingerprintKey(rule)))
    .map((rule) => [fingerprintKey(rule), rule]));
  for (const [key, rule] of newRules) {
    const previous = mergedRules.get(key);
    if (previous) {
      previous.expiresAt = expiresAt;
      previous.evidenceAlertIds = [...new Set([...previous.evidenceAlertIds, ...rule.evidenceAlertIds])];
    } else {
      mergedRules.set(key, rule);
    }
  }

  await mkdir(dirname(rulesPath), { recursive: true });
  await writeFile(rulesPath, `${JSON.stringify({
    schema: RULE_SCHEMA,
    generatedAt: nowDate.toISOString(),
    rules: [...mergedRules.values()],
  }, null, 2)}\n`, 'utf8');

  const alertLines = evaluated
    .filter(({ result }) => result.action === 'alert')
    .map(({ alert, result }) => JSON.stringify({
      at: nowDate.toISOString(),
      alertId: typeof alert?.id === 'string' ? alert.id : '',
      action: 'alert',
      confidence: result.confidence,
      reason: result.reason,
    }));
  if (alertLines.length) {
    await appendFile(join(xdrRoot, 'alerts.log'), `${alertLines.join('\n')}\n`, 'utf8');
  }

  return {
    denyRulesWritten: newRules.size,
    activeDenyRules: mergedRules.size,
    alertsLogged: alertLines.length,
  };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  try {
    const summary = await respond();
    process.stdout.write(`${JSON.stringify(summary)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'Response processing failed.'}\n`);
    process.exitCode = 1;
  }
}
