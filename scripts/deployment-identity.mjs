const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPO = /^[A-Za-z0-9._-]{1,100}$/u;
const SHA = /^[a-f0-9]{40}$/iu;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu;

function originalApiUrl(value) {
  if (value == null) return null;
  if (typeof value !== 'string' || value !== value.trim()) {
    throw new Error('원본 자료 주소는 쿼리 없는 HTTPS 주소여야 합니다.');
  }
  let url;
  try { url = new URL(value); } catch {
    throw new Error('원본 자료 주소는 쿼리 없는 HTTPS 주소여야 합니다.');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error('원본 자료 주소는 쿼리 없는 HTTPS 주소여야 합니다.');
  }
  return url.href;
}

export function deploymentIdentity(env, config) {
  const owner = env.VERCEL_GIT_REPO_OWNER;
  const repo = env.VERCEL_GIT_REPO_SLUG;
  const commit = env.VERCEL_GIT_COMMIT_SHA;
  const host = env.VERCEL_URL;
  const sourceUrl = originalApiUrl(config?.originalApiUrl);
  const allowedRoutes = config?.allowedRoutes;
  if (env.VERCEL_GIT_PROVIDER !== 'github' || !OWNER.test(owner || '')
      || !REPO.test(repo || '') || repo === '.' || repo === '..'
      || repo.toLowerCase().endsWith('.git') || !SHA.test(commit || '')
      || !HOST.test(host || '') || config?.step !== 1
      || typeof config.judgeIssuer !== 'string'
      || !/^https:\/\/[a-z0-9-]+\.up\.railway\.app\/defense\/judge$/iu.test(config.judgeIssuer)
      || typeof config.sampleMarker !== 'string'
      || !Array.isArray(allowedRoutes) || allowedRoutes.length < 1
      || allowedRoutes.some(route => typeof route !== 'string' || !route.trim())
      || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)) {
    throw new Error('배포 식별 정보를 확인할 수 없습니다. Vercel 시스템 환경변수와 1단계 시작 틀을 확인하세요.');
  }
  return {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: `https://github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`,
    commit: commit.toLowerCase(),
    publicAppUrl: `https://${host.toLowerCase()}`,
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    allowedRoutes,
    originalApiUrl: sourceUrl,
  };
}
