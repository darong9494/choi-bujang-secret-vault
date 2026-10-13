import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';
const deviceId = 'b'.repeat(16);

function reads(count, { intervalSeconds = 2, owner = subject, start = START,
  device = deviceId, network = 'usual', region = 'usual', source = 'judge_fixture' } = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * intervalSeconds * 1000).toISOString(),
    method: 'GET', identity: { sub: owner }, deviceId: device,
    signals: { source, network, region },
  }));
}

function minimalReads(count, { intervalSeconds = 2, owner = subject, start = START } = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * intervalSeconds * 1000).toISOString(),
    method: 'GET', identity: { sub: owner },
  }));
}

const cases = [
  { name: '정상 조회 30건', events: reads(30), expected: { action: 'observe' } },
  { name: '120건 경계', events: minimalReads(120),
    expected: { action: 'observe' } },
  { name: '제작자 통과 사례: 신호·기기 필드 없는 조회 121건', events: minimalReads(121),
    expected: { action: 'propose_revocation', reasonCode: 'burst_read', subject } },
  { name: '확인된 기기의 조회 폭주', events: reads(121),
    expected: { action: 'propose_revocation', reasonCode: 'burst_read', target: { deviceId } } },
  { name: '지역만 다른 단일 조회', events: reads(1, { region: 'unusual' }),
    expected: { action: 'observe' } },
  { name: '서로 다른 사용자 각 100건', events: [...reads(100, { network: 'unusual' }),
    ...reads(100, { owner: 'other_fixture', network: 'unusual' })].sort((a, b) => a.at.localeCompare(b.at)),
  expected: { action: 'observe' } },
  { name: '서로 다른 기기 각 100건', events: [...reads(100, { network: 'unusual' }),
    ...reads(100, { device: 'c'.repeat(16), network: 'unusual' })].sort((a, b) => a.at.localeCompare(b.at)),
  expected: { action: 'observe' } },
  { name: '10분 밖으로 흩어진 비정상 조회 200건', events: reads(200,
    { intervalSeconds: 7, network: 'unusual' }), expected: { action: 'observe' } },
  { name: '조회가 아닌 요청 121건', events: reads(121).map(event => ({ ...event, method: 'POST' })),
    expected: { action: 'observe' } },
];

// This is a practice contract, not a live engine assertion or judge score.
export async function checkDetection(detect) {
  if (typeof detect !== 'function') throw new TypeError('src/detect.mjs에서 detect 함수를 내보내야 합니다.');
  const results = [];
  for (const item of cases) {
    const actual = await detect(item.events);
    const passed = isDeepStrictEqual(actual, item.expected);
    results.push({ name: item.name, passed: Boolean(passed) });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { detect } = await import('../src/detect.mjs');
    const results = await checkDetection(detect);
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    process.stdout.write('가상 사건 연습이며 실제 접속 회수나 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`탐지 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
