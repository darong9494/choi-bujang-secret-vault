import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const FIXTURE_URL = new URL('../fixtures/persistence.json', import.meta.url);
const SECRET_PATTERNS = [
  /\b(?:password|passwd|pwd|(?:access[_-]?|refresh[_-]?|id[_-]?)?token|(?:client[_-]?)?secret|api[_-]?key|access[_-]?key|private[_-]?key|authorization|cookie|set-cookie)\b["']?\s*[:=]/iu,
  /(?:비밀번호|비밀키|토큰|개인키)\s*[:=]/u,
  /\b(?:Bearer|Basic)\s+\S/iu,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
  /\b(?:sb_secret_|sb_publishable_|ghp_|github_pat_|sk-|pk-)[A-Za-z0-9_.-]+/u,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/u,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u,
  /[a-z][a-z0-9+.-]*:\/\/[^\s/@]+(?::[^\s/@]*)?@/iu,
  /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu,
  /\b[A-Za-z0-9_+/=-]{40,}\b/u,
];

function safeText(value) {
  if (typeof value !== 'string') return '';
  // Redact the whole field so spaces, quotes and multiline credentials cannot leak.
  return SECRET_PATTERNS.some(pattern => pattern.test(value)) ? '[REDACTED]' : value;
}

export function extractAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'persistence'
      || !Array.isArray(fixture.alerts)) {
    throw new TypeError('지속성 경보 묶음 형식이 아닙니다.');
  }
  // Preserve one row per alert, even if optional fields are missing or malformed.
  return Array.from(fixture.alerts, alert => ({
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: safeText(alert?.rule?.description),
  }));
}

export async function readAlerts() {
  return extractAlerts(JSON.parse(await readFile(FIXTURE_URL, 'utf8')));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const rows = await readAlerts();
    const lines = rows.map(row => JSON.stringify(row)
      .replace(/\u2028/gu, '\\u2028').replace(/\u2029/gu, '\\u2029'));
    process.stdout.write(lines.length ? `${lines.join('\n')}\n` : '');
  } catch {
    // Parsing errors may include input fragments; do not print the original error.
    process.stderr.write('경보 파일을 읽거나 형식을 확인하지 못했습니다.\n');
    process.exitCode = 1;
  }
}
