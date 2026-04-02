import { auth } from '@/auth';
import prisma from '@/lib/prisma';
import { verifyMfaChallenge } from '@/lib/security/mfa';
import { revokeAdminStepUpTokens } from '@/lib/security/step-up';
import { mfaChallengeSchema } from '@/lib/validations/auth';

export async function POST(request: Request): Promise<Response> {
  const session = await auth();

  if (!session?.user?.id) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const requestBody = (await request.json().catch(() => ({}))) as unknown;
  const parsedBody = mfaChallengeSchema.safeParse(requestBody);

  if (!parsedBody.success) {
    return Response.json({ error: 'Invalid MFA challenge payload' }, { status: 400 });
  }

  const user = await prisma.user.findUnique({
    where: {
      id: session.user.id,
    },
    select: {
      mfaEnabled: true,
      mfaSecretEncrypted: true,
      mfaRecoveryCodeHashes: true,
    },
  });

  if (!user?.mfaEnabled) {
    return Response.json({ ok: true });
  }

  const challenge = verifyMfaChallenge({
    mfaEnabled: user.mfaEnabled,
    mfaSecretEncrypted: user.mfaSecretEncrypted,
    mfaRecoveryCodeHashes: user.mfaRecoveryCodeHashes,
    code: parsedBody.data.code,
    backupCode: parsedBody.data.backupCode,
  });

  if (!challenge.verified) {
    return Response.json({ error: 'Invalid MFA challenge' }, { status: 403 });
  }

  await prisma.user.update({
    where: {
      id: session.user.id,
    },
    data: {
      mfaEnabled: false,
      mfaEnabledAt: null,
      mfaSecretEncrypted: null,
      mfaPendingSecretEncrypted: null,
      mfaPendingExpiresAt: null,
      mfaRecoveryCodeHashes: [],
      mfaLastVerifiedAt: null,
    },
  });

  await revokeAdminStepUpTokens(session.user.id);

  return Response.json({ ok: true });
}
