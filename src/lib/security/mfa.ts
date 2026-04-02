import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';

import { env } from '@/lib/env';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const RECOVERY_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

const TOTP_DEFAULT_DIGITS = 6;
const TOTP_DEFAULT_PERIOD_SECONDS = 30;
const MFA_SETUP_TTL_MS = 1000 * 60 * 10;

const BASE32_CHAR_TO_VALUE = new Map(
  [...BASE32_ALPHABET].map((character, index) => [character, index])
);

type VerifyTotpOptions = {
  now?: number;
  window?: number;
  digits?: number;
  periodSeconds?: number;
};

type VerifyMfaChallengeInput = {
  mfaEnabled: boolean;
  mfaSecretEncrypted: string | null;
  mfaRecoveryCodeHashes: string[];
  code?: string | null;
  backupCode?: string | null;
};

type VerifyMfaChallengeResult = {
  verified: boolean;
  method: 'totp' | 'backup' | null;
  remainingRecoveryCodeHashes?: string[];
};

function normalizeBase32(value: string): string {
  return value.replaceAll(/\s+/g, '').replaceAll(/=+$/g, '').toUpperCase();
}

function encodeBase32(bytes: Uint8Array): string {
  let output = '';
  let buffer = 0;
  let bits = 0;

  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      const index = (buffer >> (bits - 5)) & 31;
      output += BASE32_ALPHABET[index] ?? '';
      bits -= 5;
    }
  }

  if (bits > 0) {
    const index = (buffer << (5 - bits)) & 31;
    output += BASE32_ALPHABET[index] ?? '';
  }

  return output;
}

function decodeBase32(value: string): Uint8Array {
  const normalized = normalizeBase32(value);
  let buffer = 0;
  let bits = 0;
  const bytes: number[] = [];

  for (const character of normalized) {
    const mapped = BASE32_CHAR_TO_VALUE.get(character);

    if (mapped === undefined) {
      throw new Error('Invalid MFA secret format.');
    }

    buffer = (buffer << 5) | mapped;
    bits += 5;

    while (bits >= 8) {
      const byte = (buffer >> (bits - 8)) & 0xff;
      bytes.push(byte);
      bits -= 8;
    }
  }

  return Uint8Array.from(bytes);
}

function resolveMfaEncryptionKey(): Buffer {
  const rawKey = env.MFA_ENCRYPTION_KEY?.trim();

  if (!rawKey) {
    throw new Error('MFA_ENCRYPTION_KEY is required for MFA operations.');
  }

  if (/^[0-9a-fA-F]{64}$/.test(rawKey)) {
    return Buffer.from(rawKey, 'hex');
  }

  if (rawKey.length === 32) {
    return Buffer.from(rawKey, 'utf8');
  }

  const base64Payload = rawKey.startsWith('base64:') ? rawKey.slice(7) : rawKey;

  if (/^[A-Za-z0-9+/]+={0,2}$/.test(base64Payload)) {
    const decoded = Buffer.from(base64Payload, 'base64');

    if (decoded.length === 32) {
      return decoded;
    }
  }

  throw new Error(
    'MFA_ENCRYPTION_KEY must be exactly 32 bytes (plain text, 64-char hex, or base64).'
  );
}

function calculateHotp(secretBytes: Uint8Array, counter: number, digits: number): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

  const hmac = createHmac('sha1', Buffer.from(secretBytes)).update(counterBuffer).digest();
  const offset = (hmac.at(-1) ?? 0) & 0x0f;

  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return `${binary % 10 ** digits}`.padStart(digits, '0');
}

function randomRecoveryChunk(length: number): string {
  const random = randomBytes(length);
  let output = '';

  for (let index = 0; index < length; index += 1) {
    const source = random[index] ?? 0;
    output += RECOVERY_CODE_ALPHABET[source % RECOVERY_CODE_ALPHABET.length] ?? 'A';
  }

  return output;
}

export function generateTotpSecret(byteLength = 20): string {
  return encodeBase32(randomBytes(byteLength));
}

export function buildTotpOtpAuthUrl(params: {
  issuer: string;
  accountName: string;
  secret: string;
  periodSeconds?: number;
  digits?: number;
}): string {
  const periodSeconds = params.periodSeconds ?? TOTP_DEFAULT_PERIOD_SECONDS;
  const digits = params.digits ?? TOTP_DEFAULT_DIGITS;

  const label = `${params.issuer}:${params.accountName}`;
  const encodedLabel = encodeURIComponent(label);
  const encodedIssuer = encodeURIComponent(params.issuer);

  return `otpauth://totp/${encodedLabel}?secret=${params.secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=${digits}&period=${periodSeconds}`;
}

export function normalizeOtpCode(value: string): string {
  return value.replaceAll(/\D/g, '');
}

export function normalizeRecoveryCode(value: string): string {
  return value.replaceAll(/[^A-Za-z0-9]/g, '').toUpperCase();
}

export function hashRecoveryCode(code: string): string {
  return createHash('sha256').update(normalizeRecoveryCode(code)).digest('hex');
}

export function generateRecoveryCodes(count = 8): {
  plainCodes: string[];
  hashedCodes: string[];
} {
  const plainCodes: string[] = [];

  for (let index = 0; index < count; index += 1) {
    plainCodes.push(`${randomRecoveryChunk(4)}-${randomRecoveryChunk(4)}`);
  }

  return {
    plainCodes,
    hashedCodes: plainCodes.map((code) => hashRecoveryCode(code)),
  };
}

export function consumeRecoveryCode(
  code: string,
  storedHashes: string[]
): {
  consumed: boolean;
  remainingHashes: string[];
} {
  const candidateHash = hashRecoveryCode(code);
  const targetIndex = storedHashes.indexOf(candidateHash);

  if (targetIndex < 0) {
    return {
      consumed: false,
      remainingHashes: storedHashes,
    };
  }

  return {
    consumed: true,
    remainingHashes: storedHashes.filter((_, index) => index !== targetIndex),
  };
}

export function verifyTotpCode(
  secretBase32: string,
  code: string,
  options: VerifyTotpOptions = {}
): boolean {
  const digits = options.digits ?? TOTP_DEFAULT_DIGITS;
  const periodSeconds = options.periodSeconds ?? TOTP_DEFAULT_PERIOD_SECONDS;
  const window = options.window ?? 1;
  const now = options.now ?? Date.now();

  const normalizedCode = normalizeOtpCode(code);

  if (normalizedCode.length !== digits) {
    return false;
  }

  const secretBytes = decodeBase32(secretBase32);
  const currentCounter = Math.floor(now / 1000 / periodSeconds);

  for (let offset = -window; offset <= window; offset += 1) {
    const counter = currentCounter + offset;

    if (counter < 0) {
      continue;
    }

    if (calculateHotp(secretBytes, counter, digits) === normalizedCode) {
      return true;
    }
  }

  return false;
}

export function encryptMfaSecret(secretBase32: string): string {
  const key = resolveMfaEncryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(secretBase32, 'utf8'), cipher.final()]);

  const tag = cipher.getAuthTag();

  return `v1:${iv.toString('base64url')}:${tag.toString('base64url')}:${encrypted.toString('base64url')}`;
}

export function decryptMfaSecret(serializedPayload: string): string {
  const [version, iv, tag, payload] = serializedPayload.split(':');

  if (version !== 'v1' || !iv || !tag || !payload) {
    throw new Error('Invalid encrypted MFA payload format.');
  }

  const key = resolveMfaEncryptionKey();
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload, 'base64url')),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

export function mfaSetupExpiresAt(now = new Date()): Date {
  return new Date(now.getTime() + MFA_SETUP_TTL_MS);
}

export function isMfaSetupPendingValid(
  expiresAt: Date | null | undefined,
  now = new Date()
): boolean {
  if (!expiresAt) {
    return false;
  }

  return expiresAt.getTime() > now.getTime();
}

export function verifyMfaChallenge(input: VerifyMfaChallengeInput): VerifyMfaChallengeResult {
  if (!input.mfaEnabled) {
    return {
      verified: true,
      method: null,
    };
  }

  const otpCode = normalizeOtpCode(input.code ?? '');
  const backupCode = normalizeRecoveryCode(input.backupCode ?? '');

  if (otpCode.length > 0 && input.mfaSecretEncrypted) {
    const secret = decryptMfaSecret(input.mfaSecretEncrypted);

    if (verifyTotpCode(secret, otpCode)) {
      return {
        verified: true,
        method: 'totp',
      };
    }
  }

  if (backupCode.length > 0) {
    const consumedBackupCode = consumeRecoveryCode(backupCode, input.mfaRecoveryCodeHashes);

    if (consumedBackupCode.consumed) {
      return {
        verified: true,
        method: 'backup',
        remainingRecoveryCodeHashes: consumedBackupCode.remainingHashes,
      };
    }
  }

  return {
    verified: false,
    method: null,
  };
}
