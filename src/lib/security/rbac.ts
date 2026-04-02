import prisma from '@/lib/prisma';

export const ROLE_NAMES = {
  SUPER_ADMIN: 'SUPER_ADMIN',
  ADMIN: 'ADMIN',
  MANAGER: 'MANAGER',
  USER: 'USER',
} as const;

export const ADMIN_ROLE_NAMES = [ROLE_NAMES.SUPER_ADMIN, ROLE_NAMES.ADMIN] as const;

export async function userHasRole(userId: string, roleName: string): Promise<boolean> {
  const roleCount = await prisma.userRole.count({
    where: {
      userId,
      role: {
        name: roleName,
      },
      OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
    },
  });

  return roleCount > 0;
}

export async function userHasAnyRole(
  userId: string,
  roleNames: readonly string[]
): Promise<boolean> {
  const roleCount = await prisma.userRole.count({
    where: {
      userId,
      role: {
        name: {
          in: [...roleNames],
        },
      },
      OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
    },
  });

  return roleCount > 0;
}

export async function assignRoleToUser(
  userId: string,
  roleName: string,
  assignedById?: string
): Promise<void> {
  const role = await prisma.role.findUnique({
    where: {
      name: roleName,
    },
    select: {
      id: true,
    },
  });

  if (!role) {
    throw new Error(`Role ${roleName} does not exist`);
  }

  await prisma.userRole.upsert({
    where: {
      userId_roleId: {
        userId,
        roleId: role.id,
      },
    },
    create: {
      userId,
      roleId: role.id,
      assignedById,
    },
    update: {
      assignedById,
      expiresAt: null,
    },
  });
}
