const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export const RESOURCE_KINDS = Object.freeze({
  memo: 'memo',
  instructorAnnouncement: 'instructor_announcement',
});

export function resourceId(kind, id) {
  if (!Object.values(RESOURCE_KINDS).includes(kind)
      || (id !== 'collection' && (typeof id !== 'string' || !UUID.test(id)))) {
    throw new TypeError('invalid_resource_id');
  }
  return `${kind}:${id === 'collection' ? id : id.toLowerCase()}`;
}

export function matchesResourceIdHeader(req, expectedResourceId) {
  return typeof req?.headers?.['x-resource-id'] === 'string'
    && req.headers['x-resource-id'] === expectedResourceId;
}
