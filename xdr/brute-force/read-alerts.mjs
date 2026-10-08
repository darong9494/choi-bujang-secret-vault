import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const fixturePath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'fixtures',
  'brute-force.json',
);

const REDACTED = '[REDACTED]';
const SECRET_PATTERNS = [
  /\b(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*[^\s,;]+/gi,
  /\bBearer\s+[^\s,;]+/gi,
  /\b(?:sk|pk|ghp|github_pat|eyJ)[A-Za-z0-9_.-]{12,}\b/g,
];

function safeText(value) {
  if (typeof value !== 'string') return '';
  return SECRET_PATTERNS.reduce((text, pattern) => text.replace(pattern, REDACTED), value);
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  if (!Array.isArray(fixture.alerts)) {
    throw new TypeError('Fixture alerts must be an array.');
  }

  return fixture.alerts.map((alert) => ({
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: safeText(alert?.rule?.description),
  }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const alerts = await readAlerts();
  const lines = alerts.map((alert) => JSON.stringify(alert));
  if (lines.length !== alerts.length) {
    throw new Error('Alert count does not match output line count.');
  }
  process.stdout.write(`${lines.join('\n')}\n`);
}
