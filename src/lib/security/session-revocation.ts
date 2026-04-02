import prisma from '@/lib/prisma';

export const SESSION_COOKIE_NAMES = [
  '__Secure-authjs.session-token',
  'authjs.session-token',
  '__Secure-next-auth.session-token',
  'next-auth.session-token',
] as const;

type RevocationReason =
  | 'USER_LOGOUT'
  | 'ADMIN_REVOKED'
  | 'PASSWORD_CHANGED'
  | 'ROLE_CHANGED'
  | 'ACCOUNT_BLOCKED'
  | 'COMPROMISED';

export async function revokeSessionByToken(
  sessionToken: string,
  reason: RevocationReason = 'USER_LOGOUT'
): Promise<number> {
  if (!sessionToken) {
    return 0;
  }

  const result = await prisma.session.updateMany({
    where: {
      sessionToken,
      revokedAt: null,
    },
    data: {
      revokedAt: new Date(),
      revokedReason: reason,
    },
  });

  return result.count;
}

export async function revokeAllUserSessions(
  userId: string,
  reason: RevocationReason = 'ADMIN_REVOKED'
): Promise<void> {
  const now = new Date();

  await prisma.$transaction([
    prisma.session.updateMany({
      where: {
        userId,
        revokedAt: null,
      },
      data: {
        revokedAt: now,
        revokedReason: reason,
      },
    }),
    prisma.verificationToken.updateMany({
      where: {
        identifier: userId,
        type: 'STEP_UP',
        consumedAt: null,
      },
      data: {
        consumedAt: now,
      },
    }),
    prisma.user.update({
      where: { id: userId },
      data: {
        authVersion: {
          increment: 1,
        },
      },
    }),
  ]);
}

export async function isSessionActive(sessionToken: string): Promise<boolean> {
  if (!sessionToken) {
    return false;
  }

  const session = await prisma.session.findUnique({
    where: { sessionToken },
    select: {
      revokedAt: true,
      expires: true,
      user: {
        select: {
          status: true,
          isBlocked: true,
        },
      },
    },
  });

  if (!session) {
    return false;
  }

  if (session.revokedAt) {
    return false;
  }

  if (session.expires <= new Date()) {
    return false;
  }

  if (session.user.isBlocked || session.user.status !== 'ACTIVE') {
    return false;
  }

  return true;
}

export async function touchSession(sessionToken: string): Promise<void> {
  if (!sessionToken) {
    return;
  }

  await prisma.session.updateMany({
    where: {
      sessionToken,
      revokedAt: null,
    },
    data: {
      lastSeenAt: new Date(),
    },
  });
}
