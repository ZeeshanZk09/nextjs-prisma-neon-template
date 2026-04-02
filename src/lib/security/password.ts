import { hash, verify } from '@node-rs/argon2';

import { env } from '@/lib/env';

const ARGON2_OPTIONS = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
  outputLen: 32,
};

function withPepper(input: string): string {
  const pepper = env.AUTH_PASSWORD_PEPPER;

  if (!pepper) {
    return input;
  }

  return `${input}${pepper}`;
}

export async function hashPassword(password: string): Promise<string> {
  return hash(withPepper(password), ARGON2_OPTIONS);
}

export async function verifyPassword(password: string, passwordHash: string): Promise<boolean> {
  return verify(passwordHash, withPepper(password));
}
