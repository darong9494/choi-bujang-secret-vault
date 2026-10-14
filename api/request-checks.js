import { readFileSync } from 'node:fs';
import { requireStudentIdentity } from './notes.js';
import { createRequestChecksHandler } from '../src/request-checks-service.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
export default createRequestChecksHandler({ config, verifyIdentity: requireStudentIdentity });
