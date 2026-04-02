import { auth } from '@/auth';
import prisma from '@/lib/prisma';
import {
  decryptMfaSecret,
  generateRecoveryCodes,
  isMfaSetupPendingValid,
  normalizeOtpCode,
  verifyTotpCode,
} from '@/lib/security/mfa';
import { mfaEnrollVerifySchema } from '@/lib/validations/auth';

export async function POST(request: Request): Promise<Response> {
  const session = await auth();

  if (!session?.user?.id) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const requestBody = (await request.json().catch(() => ({}))) as unknown;
  const parsedBody = mfaEnrollVerifySchema.safeParse(requestBody);

  if (!parsedBody.success) {
    return Response.json({ error: 'Invalid verification payload' }, { status: 400 });
  }

  const user = await prisma.user.findUnique({
    where: {
      id: session.user.id,
    },
    select: {
      mfaEnabled: true,
      mfaPendingSecretEncrypted: true,
      mfaPendingExpiresAt: true,
    },
  });

  if (!user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  if (user.mfaEnabled) {
    return Response.json({ error: 'MFA is already enabled' }, { status: 409 });
  }

  if (!user.mfaPendingSecretEncrypted || !isMfaSetupPendingValid(user.mfaPendingExpiresAt)) {
    return Response.json({ error: 'No active MFA enrollment request' }, { status: 400 });
  }

  const secret = decryptMfaSecret(user.mfaPendingSecretEncrypted);
  const verified = verifyTotpCode(secret, normalizeOtpCode(parsedBody.data.code));

  if (!verified) {
    return Response.json({ error: 'Invalid authenticator code' }, { status: 400 });
  }

  const recoveryCodes = generateRecoveryCodes();

  await prisma.user.update({
    where: {
      id: session.user.id,
    },
    data: {
      mfaEnabled: true,
      mfaEnabledAt: new Date(),
      mfaSecretEncrypted: user.mfaPendingSecretEncrypted,
      mfaPendingSecretEncrypted: null,
      mfaPendingExpiresAt: null,
      mfaRecoveryCodeHashes: recoveryCodes.hashedCodes,
      mfaLastVerifiedAt: new Date(),
    },
  });

  return Response.json({
    ok: true,
    recoveryCodes: recoveryCodes.plainCodes,
  });
}
