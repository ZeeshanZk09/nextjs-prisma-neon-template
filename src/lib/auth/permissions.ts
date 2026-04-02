import { auth } from '@/auth';
import { cookies } from 'next/headers';

import prisma from '@/lib/prisma';
import { ADMIN_STEP_UP_COOKIE_NAME, hasValidAdminStepUpToken } from '@/lib/security/step-up';

export class UnauthorizedError extends Error {
  constructor(message = 'Unauthorized') {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

export class ForbiddenError extends Error {
  constructor(message = 'Forbidden') {
    super(message);
    this.name = 'ForbiddenError';
  }
}

export async function checkUserPermission(userId: string, permission: string): Promise<boolean> {
  const hasSuperAdminRole = await prisma.userRole.count({
    where: {
      userId,
      role: {
        name: 'SUPER_ADMIN',
      },
      OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
    },
  });

  if (hasSuperAdminRole > 0) {
    return true;
  }

  const rolePermissionCount = await prisma.userRole.count({
    where: {
      userId,
      OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
      role: {
        permissions: {
          some: {
            permission: {
              name: permission,
            },
          },
        },
      },
    },
  });

  return rolePermissionCount > 0;
}

export async function requirePermission(permission: string) {
  const session = await auth();

  if (!session?.user?.id) {
    throw new UnauthorizedError();
  }

  const hasPermission = await checkUserPermission(session.user.id, permission);

  if (!hasPermission) {
    throw new ForbiddenError();
  }

  return session;
}

export async function requireAdminStepUp(userId: string): Promise<void> {
  const user = await prisma.user.findUnique({
    where: {
      id: userId,
    },
    select: {
      mfaEnabled: true,
    },
  });

  if (!user?.mfaEnabled) {
    throw new ForbiddenError('MFA enrollment required for this action.');
  }

  const cookieStore = await cookies();
  const stepUpToken = cookieStore.get(ADMIN_STEP_UP_COOKIE_NAME)?.value ?? '';

  if (!stepUpToken) {
    throw new ForbiddenError('MFA step-up is required for this action.');
  }

  const hasStepUp = await hasValidAdminStepUpToken(userId, stepUpToken);

  if (!hasStepUp) {
    throw new ForbiddenError('MFA step-up is required for this action.');
  }
}
