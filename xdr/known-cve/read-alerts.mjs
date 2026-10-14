import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/known-cve.json', import.meta.url);
const SECRET_LIKE = [
  /\b(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key)\b["']?\s*[:=]/iu,
  /(?:비밀번호|비밀키|토큰|개인키)\s*[:=]/u,
  /\bBearer\s+\S/iu,
  /-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----/u,
  /\b(?:sb_secret_|sb_publishable_|ghp_|github_pat_|sk-|pk-)[A-Za-z0-9_.-]+/u,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/u,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u,
  /[a-z][a-z0-9+.-]*:\/\/[^\s/@]+(?::[^\s/@]*)?@/iu,
  /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu,
  /\b[A-Za-z0-9_+/=-]{40,}\b/u,
];

function safeText(value) {
  if (typeof value !== 'string') return '';
  // Hide the entire field, including quoted or multiline values, if suspicious.
  return SECRET_LIKE.some(pattern => pattern.test(value)) ? '[REDACTED]' : value;
}

export function extractAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'known-cve'
      || !Array.isArray(fixture.alerts)) {
    throw new TypeError('알려진 취약점 경보 묶음 형식이 아닙니다.');
  }
  return Array.from(fixture.alerts, alert => ({
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: safeText(alert?.rule?.description),
  }));
}

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  return extractAlerts(fixture);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const alerts = await readAlerts();
    // JSONL escapes embedded newlines; each source alert produces exactly one line.
    const lines = alerts.map(alert => JSON.stringify(alert));
    process.stdout.write(lines.length ? `${lines.join('\n')}\n` : '');
  } catch {
    // Parser errors may contain input fragments. Never print the original error.
    process.stderr.write('경보 파일을 읽거나 형식을 확인하지 못했습니다.\n');
    process.exitCode = 1;
  }
}
