// 탐지 결과만 제안합니다. 실제 접속 회수는 이 함수에서 실행하지 않습니다.
// 입력은 계약 형식의 로컬 가상 사건입니다. 브라우저 값으로 검증 상태를 만들지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsByIdentityAndDevice = new Map();
  for (const event of events) {
    const subject = event?.identity?.sub;
    const at = typeof event?.at === 'string' ? Date.parse(event.at) : Number.NaN;
    const suppliedDeviceId = event?.deviceId;
    const deviceId = typeof suppliedDeviceId === 'string'
      && /^[a-f0-9]{16}$/u.test(suppliedDeviceId) ? suppliedDeviceId : null;

    if (event?.method !== 'GET' || typeof subject !== 'string' || !subject.trim()
        || !Number.isFinite(at)) continue;

    const key = `${subject}\u0000${deviceId ?? ''}`;
    const reads = readsByIdentityAndDevice.get(key) ?? { subject, deviceId, timestamps: [] };
    reads.timestamps.push(at);
    readsByIdentityAndDevice.set(key, reads);
  }

  for (const { subject, deviceId, timestamps } of readsByIdentityAndDevice.values()) {
    timestamps.sort((a, b) => a - b);
    let first = 0;
    for (let last = 0; last < timestamps.length; last += 1) {
      while (timestamps[last] - timestamps[first] >= WINDOW_MS) first += 1;
      if (last - first + 1 > READ_LIMIT) {
        const proposal = { action: 'propose_revocation', reasonCode: 'burst_read' };
        if (deviceId) proposal.target = { deviceId };
        else proposal.subject = subject;
        return proposal;
      }
    }
  }

  return { action: 'observe' };
}
