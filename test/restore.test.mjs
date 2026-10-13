import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { restoreMemo } from '../src/restore.mjs';

const A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const NOTE = '11111111-1111-4111-8111-111111111111';
const content = '가상 메모 백업 내용';
const hash = createHash('sha256').update(content).digest('hex');
const backup = { note_id: NOTE, owner_id: A, title: '복구 대상', content, content_sha256: hash };

function mockRequest({ backups = [backup], current = [{ id: NOTE, owner_id: A }] } = {}) {
  const calls = [];
  const request = async (url, _key, options = {}) => {
    const parsed = new URL(url);
    calls.push({ path: parsed.pathname, query: parsed.searchParams, options });
    if (parsed.pathname.endsWith('/note_backups')) return { ok: true, json: async () => backups };
    if (options.method === 'PATCH') {
      return { ok: true, json: async () => [{ id: NOTE, owner_id: A }] };
    }
    return { ok: true, json: async () => current };
  };
  return { calls, request };
}

test('owner A restores one memo from a hash-verified backup without touching audit data', async () => {
  const { calls, request } = mockRequest();
  const result = await restoreMemo({ identity: { kind: 'student', userId: A }, id: NOTE,
    databaseRequest: request, supabaseUrl: 'https://db.example',
    supabaseSecretKey: 'fixture' });
  assert.equal(result.status, 200);
  const update = calls.find(call => call.options.method === 'PATCH');
  assert.equal(calls.filter(call => call.options.method === 'PATCH').length, 1);
  assert.deepEqual(JSON.parse(update.options.body), { title: backup.title, content });
  assert.equal(update.query.get('id'), `eq.${NOTE}`);
  assert.equal(update.query.get('owner_id'), `eq.${A}`);
  assert.equal(Object.hasOwn(JSON.parse(update.options.body), 'owner_id'), false);
});

test('owner B cannot read or restore owner A memo backup', async () => {
  const { calls, request } = mockRequest();
  const result = await restoreMemo({ identity: { kind: 'student', userId: B }, id: NOTE,
    databaseRequest: request, supabaseUrl: 'https://db.example',
    supabaseSecretKey: 'fixture' });
  assert.equal(result.status, 404);
  assert.equal(calls[0].query.get('owner_id'), `eq.${B}`);
  assert.equal(calls.some(call => call.options.method === 'PATCH'), false);
});

test('restore rejects changed backup content hash', async () => {
  const corrupt = { ...backup, content: '변조된 가상 내용' };
  const { request } = mockRequest({ backups: [corrupt] });
  const tampered = await restoreMemo({ identity: { kind: 'student', userId: A }, id: NOTE,
    databaseRequest: request, supabaseUrl: 'https://db.example',
    supabaseSecretKey: 'fixture' });
  assert.equal(tampered.status, 409);
});

test('restore rejects a memo that no longer belongs to the authenticated owner', async () => {
  const { calls, request } = mockRequest({ current: [{ id: NOTE, owner_id: B }] });
  const result = await restoreMemo({ identity: { kind: 'student', userId: A }, id: NOTE,
    databaseRequest: request, supabaseUrl: 'https://db.example',
    supabaseSecretKey: 'fixture' });
  assert.equal(result.status, 404);
  assert.equal(calls.some(call => call.options.method === 'PATCH'), false);
});
