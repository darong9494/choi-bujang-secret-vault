import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { createSnapshot, diffPolicy, fileHash, planRestore, readCurrentPolicy,
  sealSnapshot, verifySnapshot } from '../scripts/policy-restore.mjs';

const ROUTES = [{ service: 'notes', method: 'GET', pathPattern: '/api/notes', zone: 'my-notes' }];
const baseline = { schema: 'aleph.policy.snapshot.v1', policyRevision: 9,
  verifiedCommit: 'abc1234def', note: '가상 정책', allowedRoutes: ROUTES,
  files: { 'src/decider.mjs': fileHash('decider-v1'), 'src/detect.mjs': fileHash('detect-v1') } };
const snapshot = sealSnapshot(baseline);
const same = { allowedRoutes: ROUTES, files: { ...baseline.files } };
const readCommitFile = (_commit, path) => ({
  'aleph.config.json': JSON.stringify({ allowedRoutes: ROUTES }),
  'src/decider.mjs': 'decider-v1', 'src/detect.mjs': 'detect-v1',
})[path];

test('정상 사본 봉인을 검증하고 변조된 사본은 거부한다', () => {
  assert.equal(verifySnapshot(snapshot), null);
  assert.match(verifySnapshot({ ...snapshot, policyRevision: 8 }), /봉인/u);
  assert.match(verifySnapshot(null), /형식/u);
});

test('현재 정책과 다른 항목만 미리 보여 준다', () => {
  assert.deepEqual(diffPolicy(snapshot, same), []);
  const current = { allowedRoutes: [...ROUTES, { service: 'notes', method: 'POST', pathPattern: '/api/notes' }],
    files: { ...same.files, 'src/decider.mjs': fileHash('tampered') } };
  assert.deepEqual(diffPolicy(snapshot, current).map(change => change.item),
    ['aleph.config.json 의 allowedRoutes', 'src/decider.mjs']);
});

test('복원 계획은 검증한 파일만 되돌리고 허용 경로만 별도 표시한다', () => {
  const current = { allowedRoutes: [...ROUTES, { method: 'POST', pathPattern: '/api/restore/:noteId' }],
    files: { ...same.files, 'src/decider.mjs': fileHash('changed') } };
  const plan = planRestore({ snapshot, current, readCommitFile });
  assert.equal(plan.restoreAllowedRoutes, true);
  assert.deepEqual(plan.writes, [{ path: 'src/decider.mjs', content: 'decider-v1' }]);
  assert.throws(() => planRestore({ snapshot, current, readCommitFile: () => 'wrong' }));
});

test('저장된 사본은 실제 stage 9 커밋을 가리키고 현재 파일 기준으로 검증된다', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const stored = JSON.parse(readFileSync(join(root, 'backup', 'policy-snapshot.json'), 'utf8'));
  assert.equal(verifySnapshot(stored), null);
  assert.ok(stored.verifiedCommit.startsWith('657381c'));
  assert.ok(readCurrentPolicy(root).files['src/decider.mjs']);
  const generated = createSnapshot(root, stored.verifiedCommit);
  assert.equal(verifySnapshot(generated), null);
});
