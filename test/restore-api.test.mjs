import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRestoreApi, loadBackupFromEnv, noteHash } from '../src/restore-api.mjs';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const NOTE_B = '33333333-3333-4333-8333-333333333333';
const NOTE_B2 = '44444444-4444-4444-8444-444444444444';
const NOTE_A = '55555555-5555-4555-8555-555555555555';
const original = { id: NOTE_B, owner_id: B, title: '가상 메모', content: '가상 원본' };
const entry = { ...original, sha256: noteHash(original) };
const backup = [entry,
  { id: NOTE_B2, owner_id: B, title: '가상 둘째', content: '둘째 원본',
    sha256: noteHash({ id: NOTE_B2, owner_id: B, title: '가상 둘째', content: '둘째 원본' }) },
  { id: NOTE_A, owner_id: A, title: 'A 가상 메모', content: 'A 원본',
    sha256: noteHash({ id: NOTE_A, owner_id: A, title: 'A 가상 메모', content: 'A 원본' }) }];

const verify = async auth => ({ 'Bearer A': { userId: A }, 'Bearer B': { userId: B } }[auth] ?? null);

function fakeDb(initial = []) {
  const rows = new Map(initial.map(row => [row.id, { ...row }]));
  const mine = (id, owner) => { const row = rows.get(id); return row?.owner_id === owner ? row : null; };
  return {
    rows,
    async get(id, owner) { const row = mine(id, owner); return row ? { ...row } : null; },
    async insert(row) { if (rows.has(row.id)) return false; rows.set(row.id, { ...row }); return true; },
    async update(id, owner, patch) { const row = mine(id, owner); if (!row) return null; Object.assign(row, patch); return row; },
  };
}

function call(handler, { method = 'POST', auth, noteId = NOTE_B } = {}) {
  return new Promise(resolve => {
    const headers = {};
    const response = {
      status(code) { response.code = code; return response; },
      setHeader(key, value) { headers[key.toLowerCase()] = value; },
      json(body) { resolve({ code: response.code, body, headers }); },
    };
    handler({ method, headers: { authorization: auth }, query: { noteId } }, response);
  });
}

function api(db, readBackup = async () => backup) {
  return createRestoreApi({ verify, db, loadBackup: readBackup });
}

test('B의 변조된 메모 한 건만 복구하고 ID·소유자·제목·내용 해시를 다시 읽어 확인한다', async () => {
  const db = fakeDb([{ ...original, content: '변조된 가상 내용' },
    { ...backup[1], content: '변경된 둘째' }]);
  const out = await call(api(db), { auth: 'Bearer B' });
  assert.equal(out.code, 200);
  assert.deepEqual(out.body, { id: NOTE_B, restored: true, sha256: entry.sha256 });
  assert.equal(noteHash(db.rows.get(NOTE_B)), entry.sha256);
  assert.equal(db.rows.get(NOTE_B2).content, '변경된 둘째');
  assert.equal(out.headers['cache-control'], 'no-store');
});

test('삭제된 메모는 복원하고 이미 같은 메모면 쓰지 않는다', async () => {
  const missing = fakeDb([]);
  const restored = await call(api(missing), { auth: 'Bearer B' });
  assert.equal(restored.code, 200);
  assert.equal(noteHash(missing.rows.get(NOTE_B)), entry.sha256);

  const unchanged = fakeDb([original]);
  const same = await call(api(unchanged), { auth: 'Bearer B' });
  assert.deepEqual(same.body, { id: NOTE_B, restored: false, sha256: entry.sha256 });
});

test('B는 A의 메모를 복원할 수 없고 기존 행을 바꾸지 않는다', async () => {
  const db = fakeDb([{ id: NOTE_A, owner_id: A, title: 'A 가상 메모', content: '변조' }]);
  const out = await call(api(db), { auth: 'Bearer B', noteId: NOTE_A });
  assert.equal(out.code, 404);
  assert.equal(db.rows.get(NOTE_A).content, '변조');
});

test('사본이 없거나 변조되었으면 복원 전에 멈춘다', async () => {
  const db = fakeDb([{ ...original, content: '변조된 가상 내용' }]);
  assert.equal((await call(api(db, async () => null), { auth: 'Bearer B' })).code, 503);
  const forged = [{ ...entry, content: '다른 가상 내용' }];
  const bad = await call(api(db, async () => forged), { auth: 'Bearer B' });
  assert.equal(bad.code, 409);
  assert.equal(bad.body.error, 'BACKUP_INVALID');
  assert.equal(db.rows.get(NOTE_B).content, '변조된 가상 내용');
});

test('복구 후 다시 읽은 해시가 다르면 성공으로 보고하지 않고 재시도하지 않는다', async () => {
  const db = fakeDb([{ ...original, content: '변조된 가상 내용' }]);
  let writes = 0;
  const unstable = { ...db, async update(id, owner, patch) {
    writes += 1;
    return db.update(id, owner, { ...patch, content: '예상 밖 결과' });
  } };
  const out = await call(api(unstable), { auth: 'Bearer B' });
  assert.equal(out.code, 500);
  assert.equal(out.body.error, 'RESTORE_MISMATCH');
  assert.equal(writes, 1);
});

test('로그인·메서드·ID 오류는 차단하고 백업 JSON 파싱은 제한한다', async () => {
  const db = fakeDb([]);
  assert.equal((await call(api(db), { noteId: NOTE_B })).code, 401);
  assert.equal((await call(api(db), { method: 'GET', auth: 'Bearer B' })).code, 405);
  assert.equal((await call(api(db), { auth: 'Bearer B', noteId: 'bad' })).code, 400);
  assert.equal(loadBackupFromEnv({}), null);
  assert.equal(loadBackupFromEnv({ NOTES_BACKUP_JSON: '{bad' }), null);
  assert.deepEqual(loadBackupFromEnv({ NOTES_BACKUP_JSON: JSON.stringify(backup) }), backup);
  assert.equal(loadBackupFromEnv({ NOTES_BACKUP_JSON: 'x'.repeat(1024 * 1024 + 1) }), null);
});
