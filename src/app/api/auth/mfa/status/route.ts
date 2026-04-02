import { auth } from '@/auth';
import prisma from '@/lib/prisma';
import { isMfaSetupPendingValid } from '@/lib/security/mfa';

export async function GET(): Promise<Response> {
  const session = await auth();

  if (!session?.user?.id) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const user = await prisma.user.findUnique({
    where: {
      id: session.user.id,
    },
    select: {
      mfaEnabled: true,
      mfaEnabledAt: true,
      mfaPendingExpiresAt: true,
      mfaLastVerifiedAt: true,
      mfaRecoveryCodeHashes: true,
    },
  });

  if (!user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  return Response.json({
    ok: true,
    mfaEnabled: user.mfaEnabled,
    mfaEnabledAt: user.mfaEnabledAt,
    mfaPending: isMfaSetupPendingValid(user.mfaPendingExpiresAt),
    mfaPendingExpiresAt: user.mfaPendingExpiresAt,
    mfaLastVerifiedAt: user.mfaLastVerifiedAt,
    backupCodesRemaining: user.mfaRecoveryCodeHashes.length,
  });
}
