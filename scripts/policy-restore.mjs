import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SNAPSHOT_PATH = 'backup/policy-snapshot.json';
const POLICY_FILES = ['src/decider.mjs', 'src/detect.mjs'];
const SCHEMA = 'aleph.policy.snapshot.v1';
const COMMIT = /^[0-9a-f]{7,40}$/u;
const dashed = hex => hex.match(/.{8}/gu).join('-');
const DASHED_HASH = /^[0-9a-f]{8}(?:-[0-9a-f]{8}){7}$/u;

export function fileHash(text) {
  return dashed(createHash('sha256').update(String(text).replace(/\r\n/gu, '\n')).digest('hex'));
}

const sealOf = body => dashed(createHash('sha256').update(JSON.stringify(body)).digest('hex'));

export function sealSnapshot(body) {
  return { ...body, sha256: sealOf(body) };
}

export function verifySnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) return '사본 형식이 아닙니다.';
  const { sha256, ...body } = snapshot;
  if (body.schema !== SCHEMA) return '사본 형식(schema)이 맞지 않습니다.';
  if (!Number.isInteger(body.policyRevision) || body.policyRevision < 1) return '정책 버전(policyRevision)이 없습니다.';
  if (typeof body.verifiedCommit !== 'string' || !COMMIT.test(body.verifiedCommit)) return '검증한 커밋(verifiedCommit)이 없습니다.';
  if (!Array.isArray(body.allowedRoutes) || !body.allowedRoutes.length) return '허용 경로(allowedRoutes)가 없습니다.';
  if (!body.files || POLICY_FILES.some(path => !DASHED_HASH.test(body.files[path] ?? ''))) return '정책 파일 해시(files)가 없습니다.';
  if (typeof sha256 !== 'string' || !DASHED_HASH.test(sha256) || sha256 !== sealOf(body)) return '사본 봉인 해시가 맞지 않습니다.';
  return null;
}

export function readCurrentPolicy(root) {
  const config = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
  const files = Object.fromEntries(POLICY_FILES.map(path => [path,
    fileHash(readFileSync(join(root, path), 'utf8'))]));
  return { allowedRoutes: config.allowedRoutes ?? [], files };
}

export function diffPolicy(snapshot, current) {
  const changes = [];
  if (JSON.stringify(snapshot.allowedRoutes) !== JSON.stringify(current.allowedRoutes)) {
    changes.push({ item: 'aleph.config.json 의 allowedRoutes', kind: 'config' });
  }
  for (const path of POLICY_FILES) {
    if (snapshot.files[path] !== current.files[path]) changes.push({ item: path, kind: 'file', path });
  }
  return changes;
}

export function planRestore({ snapshot, current, readCommitFile }) {
  const reason = verifySnapshot(snapshot);
  if (reason) throw new Error(`검증 실패: ${reason}`);
  const sourceConfig = JSON.parse(readCommitFile(snapshot.verifiedCommit, 'aleph.config.json'));
  if (JSON.stringify(sourceConfig.allowedRoutes) !== JSON.stringify(snapshot.allowedRoutes)) {
    throw new Error('검증 실패: 커밋의 허용 경로가 정책 사본과 다릅니다.');
  }
  const sourceFiles = Object.fromEntries(POLICY_FILES.map(path => [path,
    readCommitFile(snapshot.verifiedCommit, path)]));
  for (const path of POLICY_FILES) {
    if (fileHash(sourceFiles[path]) !== snapshot.files[path]) {
      throw new Error(`검증 실패: ${snapshot.verifiedCommit} 의 ${path} 해시가 정책 사본과 다릅니다.`);
    }
  }
  const changes = diffPolicy(snapshot, current);
  const writes = [];
  for (const change of changes.filter(item => item.kind === 'file')) {
    writes.push({ path: change.path, content: sourceFiles[change.path] });
  }
  return { policyRevision: snapshot.policyRevision, verifiedCommit: snapshot.verifiedCommit,
    changes, writes, restoreAllowedRoutes: changes.some(item => item.kind === 'config') };
}

const gitRaw = (root, ...args) => execFileSync('git', ['-C', root, ...args], {
  encoding: 'utf8', timeout: 10000, windowsHide: true,
});
const git = (root, ...args) => gitRaw(root, ...args).trim();
const readCommitFile = root => (commit, path) => {
  if (!COMMIT.test(commit)) throw new Error('검증 실패: 커밋 값이 올바르지 않습니다.');
  return gitRaw(root, 'show', `${commit}:${path}`);
};

export function loadSnapshot(root) {
  const path = join(root, SNAPSHOT_PATH);
  if (!existsSync(path)) throw new Error(`검증 실패: 정책 사본(${SNAPSHOT_PATH})이 없어 중단합니다.`);
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch {
    throw new Error('검증 실패: 정책 사본을 읽을 수 없어 중단합니다.');
  }
}

export function createSnapshot(root, commit, policyRevision) {
  if (!COMMIT.test(commit ?? '')) throw new Error('--commit 에 검증한 커밋 해시를 넣어 주세요.');
  const read = readCommitFile(root);
  const config = JSON.parse(read(commit, 'aleph.config.json'));
  const files = Object.fromEntries(POLICY_FILES.map(path => [path,
    fileHash(read(commit, path))]));
  return sealSnapshot({ schema: SCHEMA, policyRevision: policyRevision ?? config.step,
    verifiedCommit: git(root, 'rev-parse', '--verify', `${commit}^{commit}`),
    note: '침해 전 검증된 정책 사본. 비밀값과 메모 내용은 포함하지 않습니다.',
    allowedRoutes: config.allowedRoutes, files });
}

function show(plan) {
  const lines = [`복원 정책 버전: ${plan.policyRevision} · 검증 커밋 ${plan.verifiedCommit.slice(0, 12)}`];
  if (!plan.changes.length) lines.push('변경 범위: 없음. 현재 정책이 사본과 같습니다.');
  else {
    lines.push(`변경 범위: ${plan.changes.length}개 항목`);
    for (const change of plan.changes) lines.push(`- ${change.item}`);
  }
  lines.push('보존: 다른 파일·서비스 규칙·감사 기록·메모·배포 및 심판 설정');
  return lines.join('\n');
}

function main() {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const [command = 'diff', ...args] = process.argv.slice(2);
  try {
    if (command === 'snapshot') {
      const commitArg = args.indexOf('--commit');
      const revisionArg = args.indexOf('--revision');
      const snapshot = createSnapshot(root, commitArg >= 0 ? args[commitArg + 1] : undefined,
        revisionArg >= 0 ? Number(args[revisionArg + 1]) : undefined);
      mkdirSync(join(root, 'backup'), { recursive: true });
      writeFileSync(join(root, SNAPSHOT_PATH), `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8');
      console.log(`검증 사본 생성: ${SNAPSHOT_PATH} · 정책 ${snapshot.policyRevision} · 커밋 ${snapshot.verifiedCommit.slice(0, 12)}`);
      return;
    }
    if (!['diff', 'restore'].includes(command)) throw new Error('명령은 diff, restore, snapshot 중 하나입니다.');
    const snapshot = loadSnapshot(root);
    const plan = planRestore({ snapshot, current: readCurrentPolicy(root), readCommitFile: readCommitFile(root) });
    console.log(show(plan));
    if (command === 'diff') return;
    if (!args.includes('--apply')) {
      console.log(plan.changes.length ? '미리보기만 했습니다. 실제 적용은 --apply 를 붙여 실행하세요.' : '되돌릴 항목이 없습니다.');
      return;
    }
    for (const write of plan.writes) writeFileSync(join(root, write.path), write.content, 'utf8');
    if (plan.restoreAllowedRoutes) {
      const path = join(root, 'aleph.config.json');
      const config = JSON.parse(readFileSync(path, 'utf8'));
      config.allowedRoutes = snapshot.allowedRoutes;
      writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
    }
    console.log(`정책 ${plan.changes.length}개 항목 복원 완료. 서비스 코드·감사 기록·메모는 유지했습니다.`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : '정책 복원 오류');
    process.exitCode = 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
