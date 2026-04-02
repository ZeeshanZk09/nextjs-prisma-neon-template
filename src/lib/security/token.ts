import { createHash, randomBytes } from 'node:crypto';

export function createOneTimeToken(size = 32): string {
  return randomBytes(size).toString('base64url');
}

export function hashOneTimeToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
