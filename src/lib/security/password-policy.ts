import { createHash } from 'node:crypto';

import zxcvbn from 'zxcvbn';

import { isHibpPasswordCheckEnabled } from '@/lib/env';

const UPPERCASE_REGEX = /[A-Z]/;
const LOWERCASE_REGEX = /[a-z]/;
const NUMBER_REGEX = /\d/;
const SYMBOL_REGEX = /[^A-Za-z0-9]/;

function sha1Hex(input: string): string {
  return createHash('sha1').update(input).digest('hex').toUpperCase();
}

export function validatePasswordPolicy(password: string): string[] {
  const issues: string[] = [];

  if (password.length < 12) {
    issues.push('Password must be at least 12 characters long.');
  }

  if (!UPPERCASE_REGEX.test(password)) {
    issues.push('Password must include at least one uppercase letter.');
  }

  if (!LOWERCASE_REGEX.test(password)) {
    issues.push('Password must include at least one lowercase letter.');
  }

  if (!NUMBER_REGEX.test(password)) {
    issues.push('Password must include at least one number.');
  }

  if (!SYMBOL_REGEX.test(password)) {
    issues.push('Password must include at least one symbol.');
  }

  const strength = zxcvbn(password);

  if (strength.score < 2) {
    issues.push('Password is too weak. Choose a stronger password.');
  }

  return issues;
}

export async function getPwnedPasswordCount(password: string): Promise<number> {
  const hash = sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    method: 'GET',
    headers: {
      'Add-Padding': 'true',
      'User-Agent': 'ai-social-media-auto-scheduler-security-check',
    },
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error('Password safety check is unavailable.');
  }

  const body = await response.text();
  const lines = body.split('\n');

  for (const line of lines) {
    const [lineSuffix, countValue] = line.trim().split(':');

    if (lineSuffix?.toUpperCase() === suffix) {
      const parsedCount = Number.parseInt(countValue ?? '0', 10);
      return Number.isFinite(parsedCount) ? parsedCount : 0;
    }
  }

  return 0;
}

export async function assertPasswordSecurity(password: string): Promise<void> {
  const issues = validatePasswordPolicy(password);

  if (issues.length > 0) {
    throw new Error(issues.join(' '));
  }

  if (!isHibpPasswordCheckEnabled) {
    return;
  }

  const breachCount = await getPwnedPasswordCount(password);

  if (breachCount > 0) {
    throw new Error('This password appears in known data breaches. Choose a different password.');
  }
}
