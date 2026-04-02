import { NextResponse } from 'next/server';

import { auth } from '@/auth';
import { env } from '@/lib/env';
import { getClientIpFromRequest } from '@/lib/http/request';
import prisma from '@/lib/prisma';
import { verifyMfaChallenge } from '@/lib/security/mfa';
import { ADMIN_STEP_UP_COOKIE_NAME, issueAdminStepUpToken } from '@/lib/security/step-up';
import { mfaChallengeSchema } from '@/lib/validations/auth';

export async function POST(request: Request): Promise<Response> {
  const session = await auth();

  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const requestBody = (await request.json().catch(() => ({}))) as unknown;
  const parsedBody = mfaChallengeSchema.safeParse(requestBody);

  if (!parsedBody.success) {
    return NextResponse.json({ error: 'Invalid MFA challenge payload' }, { status: 400 });
  }

  const user = await prisma.user.findUnique({
    where: {
      id: session.user.id,
    },
    select: {
      status: true,
      isBlocked: true,
      mfaEnabled: true,
      mfaSecretEncrypted: true,
      mfaRecoveryCodeHashes: true,
    },
  });

  if (user?.status !== 'ACTIVE' || user?.isBlocked) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const challenge = verifyMfaChallenge({
    mfaEnabled: user.mfaEnabled,
    mfaSecretEncrypted: user.mfaSecretEncrypted,
    mfaRecoveryCodeHashes: user.mfaRecoveryCodeHashes,
    code: parsedBody.data.code,
    backupCode: parsedBody.data.backupCode,
  });

  if (!challenge.verified) {
    return NextResponse.json({ error: 'Invalid MFA challenge' }, { status: 403 });
  }

  const updateData: {
    mfaLastVerifiedAt: Date;
    mfaRecoveryCodeHashes?: string[];
  } = {
    mfaLastVerifiedAt: new Date(),
  };

  if (challenge.remainingRecoveryCodeHashes === undefined) {
    // Keep existing backup hashes when no backup code was consumed.
  } else {
    updateData.mfaRecoveryCodeHashes = challenge.remainingRecoveryCodeHashes;
  }

  await prisma.user.update({
    where: {
      id: session.user.id,
    },
    data: updateData,
  });

  const issuedToken = await issueAdminStepUpToken({
    userId: session.user.id,
    requestedIp: getClientIpFromRequest(request),
  });

  const response = NextResponse.json({
    ok: true,
    expiresAt: issuedToken.expiresAt,
  });

  response.cookies.set(ADMIN_STEP_UP_COOKIE_NAME, issuedToken.token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: env.NODE_ENV === 'production',
    path: '/',
    expires: issuedToken.expiresAt,
  });

  return response;
}
