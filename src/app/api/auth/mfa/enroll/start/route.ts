import { auth } from '@/auth';
import prisma from '@/lib/prisma';
import {
  buildTotpOtpAuthUrl,
  encryptMfaSecret,
  generateTotpSecret,
  mfaSetupExpiresAt,
} from '@/lib/security/mfa';
import { verifyPassword } from '@/lib/security/password';
import { mfaEnrollStartSchema } from '@/lib/validations/auth';

const MFA_ISSUER = 'Resellify';

export async function POST(request: Request): Promise<Response> {
  const session = await auth();

  if (!session?.user?.id) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const requestBody = (await request.json().catch(() => ({}))) as unknown;
  const parsedBody = mfaEnrollStartSchema.safeParse(requestBody);

  if (!parsedBody.success) {
    return Response.json({ error: 'Invalid enrollment payload' }, { status: 400 });
  }

  const user = await prisma.user.findUnique({
    where: {
      id: session.user.id,
    },
    select: {
      email: true,
      passwordHash: true,
      status: true,
      isBlocked: true,
      mfaEnabled: true,
    },
  });

  if (!user?.passwordHash || user.status !== 'ACTIVE' || user.isBlocked) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const validPassword = await verifyPassword(parsedBody.data.password, user.passwordHash);

  if (!validPassword) {
    return Response.json({ error: 'Invalid credentials' }, { status: 403 });
  }

  if (user.mfaEnabled) {
    return Response.json({ error: 'MFA is already enabled' }, { status: 409 });
  }

  const secret = generateTotpSecret();
  const encryptedSecret = encryptMfaSecret(secret);
  const expiresAt = mfaSetupExpiresAt();
  const otpAuthUrl = buildTotpOtpAuthUrl({
    issuer: MFA_ISSUER,
    accountName: user.email,
    secret,
  });

  await prisma.user.update({
    where: {
      id: session.user.id,
    },
    data: {
      mfaPendingSecretEncrypted: encryptedSecret,
      mfaPendingExpiresAt: expiresAt,
    },
  });

  return Response.json({
    ok: true,
    secret,
    otpAuthUrl,
    expiresAt,
  });
}
