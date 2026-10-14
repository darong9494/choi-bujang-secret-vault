import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { extractAlerts, readAlerts } from '../xdr/persistence/read-alerts.mjs';

const fixtureUrl = new URL('../xdr/fixtures/persistence.json', import.meta.url);
const wrap = alerts => ({ schema: 'aleph.xdr.fixture.v1', moduleKey: 'persistence', alerts });

test('actual CLI prints one five-field row per source alert and preserves the source', async () => {
  const before = await readFile(fixtureUrl, 'utf8');
  const source = JSON.parse(before);
  const rows = await readAlerts();
  const output = spawnSync(process.execPath,
    [fileURLToPath(new URL('../xdr/persistence/read-alerts.mjs', import.meta.url))],
    { encoding: 'utf8', windowsHide: true });
  assert.equal(output.status, 0, output.stderr);
  assert.equal(output.stderr, '');
  const lines = output.stdout.trimEnd().split('\n');
  assert.equal(lines.length, source.alerts.length);
  assert.deepEqual(lines.map(line => JSON.parse(line)), rows);
  for (const [index, row] of rows.entries()) {
    assert.deepEqual(Object.keys(row).sort(),
      ['account', 'description', 'ruleLevel', 'sourceAddress', 'timestamp']);
    assert.equal(row.timestamp, source.alerts[index].timestamp);
    assert.equal(row.sourceAddress, source.alerts[index].data.srcip);
    assert.equal(row.account, source.alerts[index].data.srcuser ?? '');
    assert.equal(row.ruleLevel, source.alerts[index].rule.level);
    assert.equal(row.description, source.alerts[index].rule.description);
  }
  assert.equal(await readFile(fixtureUrl, 'utf8'), before);
});

test('secret-like values are fully hidden in every text field and unselected fields are omitted', () => {
  const examples = [
    'password="synthetic value with spaces"',
    '"refresh_token": "synthetic value"',
    'Bearer synthetic-credential',
    'Basic synthetic-credential',
    '-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----',
    'ghp_syntheticExampleOnly',
    'https://sample:synthetic@invalid.example/path',
    '토큰: synthetic',
    'eyJtest.eyJtest.synthetic',
    'x'.repeat(48),
  ];
  for (const text of examples) {
    const [row] = extractAlerts(wrap([{
      timestamp: text, data: { srcip: text, srcuser: text, token: 'DO_NOT_COPY' },
      rule: { level: 3, description: text }, body: 'DO_NOT_COPY',
    }]));
    assert.equal(row.ruleLevel, 3);
    for (const key of ['timestamp', 'sourceAddress', 'account', 'description']) {
      assert.equal(row[key], '[REDACTED]');
    }
    assert.ok(!JSON.stringify(row).includes('DO_NOT_COPY'));
  }
});

test('missing fields keep their row, ordinary values survive, and descriptions serialize to one line', () => {
  const rows = extractAlerts(wrap([null, {}, {
    timestamp: '2026-10-14T01:00:00Z', data: { srcip: '192.0.2.1', srcuser: 'user01' },
    rule: { description: 'first\nsecond', level: '3' },
  }]));
  assert.equal(rows.length, 3);
  assert.equal(rows[0].ruleLevel, null);
  assert.equal(rows[0].account, '');
  assert.equal(rows[2].ruleLevel, null);
  assert.equal(rows[2].account, 'user01');
  assert.equal(rows.map(row => JSON.stringify(row)).join('\n').split('\n').length, 3);
  assert.deepEqual(extractAlerts(wrap([])), []);
  assert.throws(() => extractAlerts({ alerts: [] }), TypeError);
});

test('decision module remains independent from the reader', async () => {
  const source = await readFile(new URL('../xdr/persistence/decide.mjs', import.meta.url), 'utf8');
  assert.ok(!source.includes('read-alerts'));
  assert.doesNotMatch(source, /\bimport\b|\brequire\s*\(/u);
});
