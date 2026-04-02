import 'dotenv/config';

import prisma from '../src/lib/prisma';
import { hashPassword } from '../src/lib/security/password';

const ROLE_DEFINITIONS = [
  { name: 'SUPER_ADMIN', description: 'Full system control', isImmutable: true },
  { name: 'ADMIN', description: 'Administrative operations', isImmutable: false },
  { name: 'MANAGER', description: 'Operational management role', isImmutable: false },
  { name: 'USER', description: 'Standard product user', isImmutable: false },
] as const;

const PERMISSION_DEFINITIONS = [
  { name: 'dashboard.view', description: 'Access dashboard pages' },
  { name: 'users.read', description: 'Read users' },
  { name: 'users.manage', description: 'Manage users and account status' },
  { name: 'roles.read', description: 'Read role assignments' },
  { name: 'roles.assign', description: 'Assign roles to users' },
  { name: 'billing.read', description: 'Read billing data' },
  { name: 'billing.manage', description: 'Manage subscriptions and invoices' },
  { name: 'settings.manage', description: 'Change system settings' },
  { name: 'logs.read', description: 'Read system and admin logs' },
] as const;

const ROLE_PERMISSION_MAP: Record<string, string[]> = {
  SUPER_ADMIN: PERMISSION_DEFINITIONS.map((permission) => permission.name),
  ADMIN: [
    'dashboard.view',
    'users.read',
    'users.manage',
    'roles.read',
    'roles.assign',
    'billing.read',
    'billing.manage',
    'settings.manage',
    'logs.read',
  ],
  MANAGER: ['dashboard.view', 'users.read', 'roles.read', 'billing.read', 'logs.read'],
  USER: ['dashboard.view'],
};

async function seedRolesAndPermissions(): Promise<void> {
  for (const role of ROLE_DEFINITIONS) {
    await prisma.role.upsert({
      where: { name: role.name },
      create: {
        name: role.name,
        description: role.description,
        isImmutable: role.isImmutable,
      },
      update: {
        description: role.description,
        isImmutable: role.isImmutable,
      },
    });
  }

  for (const permission of PERMISSION_DEFINITIONS) {
    await prisma.permission.upsert({
      where: { name: permission.name },
      create: {
        name: permission.name,
        description: permission.description,
      },
      update: {
        description: permission.description,
      },
    });
  }

  const roles = await prisma.role.findMany({
    select: {
      id: true,
      name: true,
    },
  });

  const permissions = await prisma.permission.findMany({
    select: {
      id: true,
      name: true,
    },
  });

  const roleIdByName = new Map(roles.map((role) => [role.name, role.id]));
  const permissionIdByName = new Map(
    permissions.map((permission) => [permission.name, permission.id])
  );

  for (const [roleName, permissionNames] of Object.entries(ROLE_PERMISSION_MAP)) {
    const roleId = roleIdByName.get(roleName);

    if (!roleId) {
      continue;
    }

    const targetPermissionIds = permissionNames
      .map((permissionName) => permissionIdByName.get(permissionName))
      .filter((permissionId): permissionId is string => Boolean(permissionId));

    await prisma.rolePermission.deleteMany({
      where: {
        roleId,
        permissionId: {
          notIn: targetPermissionIds,
        },
      },
    });

    for (const permissionId of targetPermissionIds) {
      await prisma.rolePermission.upsert({
        where: {
          roleId_permissionId: {
            roleId,
            permissionId,
          },
        },
        create: {
          roleId,
          permissionId,
        },
        update: {
          assignedAt: new Date(),
        },
      });
    }
  }
}

async function bootstrapFirstSuperAdmin(): Promise<void> {
  const activeSuperAdminCount = await prisma.userRole.count({
    where: {
      role: {
        name: 'SUPER_ADMIN',
      },
      OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
    },
  });

  if (activeSuperAdminCount > 0) {
    console.info('[seed-rbac] SUPER_ADMIN already exists. Skipping bootstrap.');
    return;
  }

  const bootstrapEmail = process.env.BOOTSTRAP_SUPER_ADMIN_EMAIL?.trim().toLowerCase();

  if (!bootstrapEmail) {
    console.warn(
      '[seed-rbac] No SUPER_ADMIN found. Set BOOTSTRAP_SUPER_ADMIN_EMAIL (and optional name/password) then rerun seed:rbac.'
    );
    return;
  }

  const superAdminRole = await prisma.role.findUnique({
    where: { name: 'SUPER_ADMIN' },
    select: { id: true },
  });

  if (!superAdminRole) {
    throw new Error('SUPER_ADMIN role missing after seed.');
  }

  let user = await prisma.user.findUnique({
    where: {
      email: bootstrapEmail,
    },
    select: {
      id: true,
      status: true,
      isBlocked: true,
    },
  });

  if (!user) {
    const bootstrapPassword = process.env.BOOTSTRAP_SUPER_ADMIN_PASSWORD;

    if (!bootstrapPassword || bootstrapPassword.length < 12) {
      throw new Error(
        'BOOTSTRAP_SUPER_ADMIN_PASSWORD must be set with at least 12 characters when creating the first SUPER_ADMIN user.'
      );
    }

    const passwordHash = await hashPassword(bootstrapPassword);
    const bootstrapName = process.env.BOOTSTRAP_SUPER_ADMIN_NAME?.trim() || 'Initial Super Admin';

    user = await prisma.user.create({
      data: {
        name: bootstrapName,
        email: bootstrapEmail,
        passwordHash,
        emailVerified: new Date(),
        status: 'ACTIVE',
        isBlocked: false,
      },
      select: {
        id: true,
        status: true,
        isBlocked: true,
      },
    });
  }

  if (user.status !== 'ACTIVE' || user.isBlocked) {
    throw new Error('Bootstrap user must be ACTIVE and not blocked before assigning SUPER_ADMIN.');
  }

  await prisma.userRole.upsert({
    where: {
      userId_roleId: {
        userId: user.id,
        roleId: superAdminRole.id,
      },
    },
    create: {
      userId: user.id,
      roleId: superAdminRole.id,
    },
    update: {
      expiresAt: null,
    },
  });

  console.info(`[seed-rbac] SUPER_ADMIN assigned to ${bootstrapEmail}`);
}

async function main(): Promise<void> {
  await seedRolesAndPermissions();
  await bootstrapFirstSuperAdmin();
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (error) => {
    console.error('[seed-rbac] Failed:', error);
    await prisma.$disconnect();
    process.exit(1);
  });
