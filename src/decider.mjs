import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const denyRulesPath = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'xdr', 'web-injection', 'deny-rules.json');
const DENY_RULE_SCHEMA = 'aleph.xdr.deny-rules.v1';

export const RULE_IDS = Object.freeze([
  'device_registered',
  'web_injection_query_deny',
  'request_allowed',
]);

async function activeDenyRules(now = Date.now()) {
  try {
    const stored = JSON.parse(await readFile(denyRulesPath, 'utf8'));
    if (stored?.schema !== DENY_RULE_SCHEMA || !Array.isArray(stored.rules)) return [];
    return stored.rules.filter((rule) => rule?.ruleId === 'web_injection_query_deny'
      && typeof rule.path === 'string'
      && Number.isSafeInteger(rule.queryLength) && rule.queryLength > 0
      && typeof rule.querySha256 === 'string' && /^[a-f0-9]{64}$/i.test(rule.querySha256)
      && Array.isArray(rule.evidenceAlertIds) && rule.evidenceAlertIds.length > 0
      && Number.isFinite(Date.parse(rule.expiresAt)) && Date.parse(rule.expiresAt) > now);
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

export async function decide(request) {
  if (request?.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  const rules = await activeDenyRules();
  const blockedByRule = rules.some((rule) => rule.path === request.path
    && rule.queryLength === request.queryLength
    && rule.querySha256.toLowerCase() === String(request.querySha256 ?? '').toLowerCase());
  if (blockedByRule) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'starter_not_ready',
      ruleIds: ['web_injection_query_deny'],
    };
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['request_allowed'],
  };
}
