import { adminStepUpTtlSeconds } from '@/lib/env';
import prisma from '@/lib/prisma';
import { createOneTimeToken, hashOneTimeToken } from '@/lib/security/token';

export const ADMIN_STEP_UP_COOKIE_NAME = 'admin_step_up';

type IssueAdminStepUpTokenInput = {
  userId: string;
  requestedIp?: string | null;
};

function stepUpTokenMarker(rawToken: string): string {
  return hashOneTimeToken(`step-up:${rawToken}`);
}

export async function issueAdminStepUpToken(input: IssueAdminStepUpTokenInput): Promise<{
  token: string;
  expiresAt: Date;
}> {
  const now = new Date();
  const token = createOneTimeToken(24);
  const tokenHash = hashOneTimeToken(token);
  const expiresAt = new Date(now.getTime() + adminStepUpTtlSeconds * 1000);

  await prisma.verificationToken.updateMany({
    where: {
      identifier: input.userId,
      type: 'STEP_UP',
      consumedAt: null,
    },
    data: {
      consumedAt: now,
    },
  });

  await prisma.verificationToken.create({
    data: {
      identifier: input.userId,
      type: 'STEP_UP',
      token: stepUpTokenMarker(token),
      tokenHash,
      expires: expiresAt,
      requestedIp: input.requestedIp ?? null,
    },
  });

  return {
    token,
    expiresAt,
  };
}

export async function hasValidAdminStepUpToken(userId: string, token: string): Promise<boolean> {
  if (!userId || !token) {
    return false;
  }

  const tokenHash = hashOneTimeToken(token);

  const activeTokenCount = await prisma.verificationToken.count({
    where: {
      identifier: userId,
      type: 'STEP_UP',
      tokenHash,
      consumedAt: null,
      expires: {
        gt: new Date(),
      },
    },
  });

  return activeTokenCount > 0;
}

export async function revokeAdminStepUpTokens(userId: string): Promise<void> {
  await prisma.verificationToken.updateMany({
    where: {
      identifier: userId,
      type: 'STEP_UP',
      consumedAt: null,
    },
    data: {
      consumedAt: new Date(),
    },
  });
}
