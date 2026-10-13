// 탐지 결과만 제안합니다. 실제 접속 회수는 이 함수에서 실행하지 않습니다.
// 입력은 계약 형식의 로컬 가상 사건입니다. 브라우저 값으로 검증 상태를 만들지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsByIdentityAndDevice = new Map();
  for (const event of events) {
    const subject = event?.identity?.sub;
    const deviceId = event?.deviceId;
    const at = typeof event?.at === 'string' ? Date.parse(event.at) : Number.NaN;
    const hasFixtureSignals = event?.signals?.source === 'judge_fixture'
      && ['usual', 'unusual'].includes(event.signals.network);

    if (!hasFixtureSignals || event.method !== 'GET'
        || typeof subject !== 'string' || !subject.trim()
        || typeof deviceId !== 'string' || !/^[a-f0-9]{16}$/u.test(deviceId)
        || !Number.isFinite(at)) continue;

    const key = `${subject}\u0000${deviceId}`;
    const reads = readsByIdentityAndDevice.get(key) ?? { deviceId, events: [] };
    reads.events.push({ at, unusualNetwork: event.signals.network === 'unusual' });
    readsByIdentityAndDevice.set(key, reads);
  }

  for (const { deviceId, events: reads } of readsByIdentityAndDevice.values()) {
    reads.sort((a, b) => a.at - b.at);
    let first = 0;
    let unusualNetworkCount = 0;
    for (let last = 0; last < reads.length; last += 1) {
      if (reads[last].unusualNetwork) unusualNetworkCount += 1;
      while (reads[last].at - reads[first].at > WINDOW_MS) {
        if (reads[first].unusualNetwork) unusualNetworkCount -= 1;
        first += 1;
      }
      if (last - first + 1 > READ_LIMIT && unusualNetworkCount > 0) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          target: { deviceId },
        };
      }
    }
  }

  return { action: 'observe' };
}
