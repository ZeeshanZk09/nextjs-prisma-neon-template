import prisma from '@/lib/prisma';
import { env } from '@/lib/env';
import { logger } from '@/lib/logger';
import { sendTransactionalEmail } from '@/lib/notifications/email';
import { hashPassword } from '@/lib/security/password';
import { assertPasswordSecurity } from '@/lib/security/password-policy';
import { ROLE_NAMES } from '@/lib/security/rbac';
import { revokeAllUserSessions } from '@/lib/security/session-revocation';
import { createOneTimeToken, hashOneTimeToken } from '@/lib/security/token';

const EMAIL_VERIFICATION_TTL_MS = 1000 * 60 * 60 * 24;
const PASSWORD_RESET_TTL_MS = 1000 * 60 * 30;

function appBaseUrl(): string {
  return env.NEXT_PUBLIC_APP_URL;
}

async function issueOneTimeAuthToken(params: {
  identifier: string;
  type: 'EMAIL_VERIFY' | 'PASSWORD_RESET';
  requestedIp?: string | null;
  ttlMs: number;
}): Promise<{ token: string; expires: Date }> {
  const token = createOneTimeToken();
  const tokenHash = hashOneTimeToken(token);
  const now = new Date();
  const expires = new Date(now.getTime() + params.ttlMs);

  await prisma.verificationToken.updateMany({
    where: {
      identifier: params.identifier,
      type: params.type,
      consumedAt: null,
    },
    data: {
      consumedAt: now,
    },
  });

  await prisma.verificationToken.create({
    data: {
      identifier: params.identifier,
      token: hashOneTimeToken(`legacy:${token}`),
      tokenHash,
      type: params.type,
      expires,
      requestedIp: params.requestedIp ?? null,
    },
  });

  return { token, expires };
}

async function consumeOneTimeAuthToken(params: {
  identifier: string;
  type: 'EMAIL_VERIFY' | 'PASSWORD_RESET';
  token: string;
}): Promise<boolean> {
  const tokenHash = hashOneTimeToken(params.token);
  const now = new Date();

  const result = await prisma.verificationToken.updateMany({
    where: {
      identifier: params.identifier,
      type: params.type,
      tokenHash,
      consumedAt: null,
      expires: {
        gt: now,
      },
    },
    data: {
      consumedAt: now,
    },
  });

  return result.count === 1;
}

function buildEmailVerificationUrl(email: string, token: string): string {
  const url = new URL('/api/auth/verify-email', appBaseUrl());
  url.searchParams.set('email', email);
  url.searchParams.set('token', token);
  return url.toString();
}

function buildPasswordResetUrl(email: string, token: string): string {
  const url = new URL('/reset-password', appBaseUrl());
  url.searchParams.set('email', email);
  url.searchParams.set('token', token);
  return url.toString();
}

async function sendEmailVerificationMessage(email: string, token: string): Promise<void> {
  const verificationUrl = buildEmailVerificationUrl(email, token);

  await sendTransactionalEmail({
    to: email,
    subject: 'Verify your email address',
    text: `Welcome to Resellify. Verify your email using this link: ${verificationUrl}`,
  });
}

async function sendPasswordResetMessage(email: string, token: string): Promise<void> {
  const resetUrl = buildPasswordResetUrl(email, token);

  await sendTransactionalEmail({
    to: email,
    subject: 'Reset your password',
    text: `Reset your password with this secure link: ${resetUrl}`,
  });
}

export async function registerUserFlow(input: {
  name: string;
  email: string;
  password: string;
  requestedIp?: string | null;
}): Promise<void> {
  const email = input.email.toLowerCase().trim();

  const existingUser = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      emailVerified: true,
      status: true,
      isBlocked: true,
    },
  });

  if (existingUser) {
    if (
      !existingUser.emailVerified &&
      existingUser.status === 'ACTIVE' &&
      !existingUser.isBlocked
    ) {
      const verificationToken = await issueOneTimeAuthToken({
        identifier: email,
        type: 'EMAIL_VERIFY',
        ttlMs: EMAIL_VERIFICATION_TTL_MS,
        requestedIp: input.requestedIp,
      });

      await sendEmailVerificationMessage(email, verificationToken.token);
    }

    return;
  }

  await assertPasswordSecurity(input.password);

  const passwordHash = await hashPassword(input.password);

  const user = await prisma.user.create({
    data: {
      name: input.name,
      email,
      passwordHash,
      status: 'ACTIVE',
      isBlocked: false,
    },
    select: {
      id: true,
    },
  });

  const defaultRole = await prisma.role.findUnique({
    where: {
      name: ROLE_NAMES.USER,
    },
    select: {
      id: true,
    },
  });

  if (defaultRole) {
    await prisma.userRole.upsert({
      where: {
        userId_roleId: {
          userId: user.id,
          roleId: defaultRole.id,
        },
      },
      create: {
        userId: user.id,
        roleId: defaultRole.id,
      },
      update: {
        expiresAt: null,
      },
    });
  }

  const verificationToken = await issueOneTimeAuthToken({
    identifier: email,
    type: 'EMAIL_VERIFY',
    ttlMs: EMAIL_VERIFICATION_TTL_MS,
    requestedIp: input.requestedIp,
  });

  await sendEmailVerificationMessage(email, verificationToken.token);
}

export async function verifyEmailFlow(input: { email: string; token: string }): Promise<boolean> {
  const email = input.email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      emailVerified: true,
    },
  });

  if (!user) {
    return false;
  }

  if (user.emailVerified) {
    return true;
  }

  const consumed = await consumeOneTimeAuthToken({
    identifier: email,
    type: 'EMAIL_VERIFY',
    token: input.token,
  });

  if (!consumed) {
    return false;
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      emailVerified: new Date(),
      failedLoginAttempts: 0,
      lockedUntil: null,
    },
  });

  return true;
}

export async function requestPasswordResetFlow(input: {
  email: string;
  requestedIp?: string | null;
}): Promise<void> {
  const email = input.email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      emailVerified: true,
      passwordHash: true,
      status: true,
      isBlocked: true,
    },
  });

  if (!user?.passwordHash || !user.emailVerified || user.status !== 'ACTIVE' || user.isBlocked) {
    return;
  }

  const resetToken = await issueOneTimeAuthToken({
    identifier: email,
    type: 'PASSWORD_RESET',
    ttlMs: PASSWORD_RESET_TTL_MS,
    requestedIp: input.requestedIp,
  });

  await sendPasswordResetMessage(email, resetToken.token);
}

export async function resetPasswordFlow(input: {
  email: string;
  token: string;
  password: string;
}): Promise<boolean> {
  const email = input.email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      status: true,
      isBlocked: true,
    },
  });

  if (!user?.id || user.status !== 'ACTIVE' || user.isBlocked) {
    return false;
  }

  const consumed = await consumeOneTimeAuthToken({
    identifier: email,
    type: 'PASSWORD_RESET',
    token: input.token,
  });

  if (!consumed) {
    return false;
  }

  await assertPasswordSecurity(input.password);

  const passwordHash = await hashPassword(input.password);

  await prisma.user.update({
    where: {
      id: user.id,
    },
    data: {
      passwordHash,
      passwordChangedAt: new Date(),
      failedLoginAttempts: 0,
      lockedUntil: null,
    },
  });

  await revokeAllUserSessions(user.id, 'PASSWORD_CHANGED');
  logger.info('auth.password_reset.completed', { userId: user.id });
  return true;
}
