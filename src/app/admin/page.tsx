import { revalidatePath } from 'next/cache';
import { cookies } from 'next/headers';
import { notFound, redirect } from 'next/navigation';

import {
  ForbiddenError,
  requireAdminStepUp,
  requirePermission,
  UnauthorizedError,
} from '@/lib/auth/permissions';
import { env } from '@/lib/env';
import { getFormBoolean, getFormString } from '@/lib/forms';
import prisma from '@/lib/prisma';
import { writeAdminActivityLog } from '@/lib/security/admin-activity';
import { verifyMfaChallenge } from '@/lib/security/mfa';
import { assignRoleToUser } from '@/lib/security/rbac';
import { revokeAllUserSessions } from '@/lib/security/session-revocation';
import { ADMIN_STEP_UP_COOKIE_NAME, issueAdminStepUpToken } from '@/lib/security/step-up';
import { mfaChallengeSchema } from '@/lib/validations/auth';
import { adminAssignRoleSchema, adminUserStatusUpdateSchema } from '@/lib/validations/admin';

function getSearchParam(
  params: Record<string, string | string[] | undefined>,
  key: string
): string {
  const value = params[key];

  if (Array.isArray(value)) {
    return value[0] ?? '';
  }

  if (typeof value === 'string') {
    return value;
  }

  return '';
}

function handlePermissionError(error: unknown): never {
  if (error instanceof UnauthorizedError) {
    redirect('/login');
  }

  if (error instanceof ForbiddenError) {
    notFound();
  }

  throw error;
}

async function requireAdminUserId(permission: string): Promise<string> {
  try {
    const session = await requirePermission(permission);
    return session.user.id;
  } catch (error) {
    return handlePermissionError(error);
  }
}

async function ensureAdminStepUp(adminId: string): Promise<void> {
  try {
    await requireAdminStepUp(adminId);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      redirect('/admin?stepUp=required');
    }

    throw error;
  }
}

async function verifyStepUpAction(formData: FormData): Promise<void> {
  'use server';

  const adminId = await requireAdminUserId('users.read');

  const parsedBody = mfaChallengeSchema.safeParse({
    code: getFormString(formData, 'stepUpCode'),
    backupCode: getFormString(formData, 'stepUpBackupCode'),
  });

  if (!parsedBody.success) {
    redirect('/admin?stepUp=invalid');
  }

  const adminUser = await prisma.user.findUnique({
    where: {
      id: adminId,
    },
    select: {
      mfaEnabled: true,
      mfaSecretEncrypted: true,
      mfaRecoveryCodeHashes: true,
    },
  });

  if (!adminUser?.mfaEnabled) {
    redirect('/admin?stepUp=enableMfa');
  }

  const challenge = verifyMfaChallenge({
    mfaEnabled: adminUser.mfaEnabled,
    mfaSecretEncrypted: adminUser.mfaSecretEncrypted,
    mfaRecoveryCodeHashes: adminUser.mfaRecoveryCodeHashes,
    code: parsedBody.data.code,
    backupCode: parsedBody.data.backupCode,
  });

  if (!challenge.verified) {
    redirect('/admin?stepUp=invalid');
  }

  const mfaUpdateData: {
    mfaLastVerifiedAt: Date;
    mfaRecoveryCodeHashes?: string[];
  } = {
    mfaLastVerifiedAt: new Date(),
  };

  if (challenge.remainingRecoveryCodeHashes === undefined) {
    // Keep existing backup hashes when no backup code was consumed.
  } else {
    mfaUpdateData.mfaRecoveryCodeHashes = challenge.remainingRecoveryCodeHashes;
  }

  await prisma.user.update({
    where: {
      id: adminId,
    },
    data: mfaUpdateData,
  });

  const issuedToken = await issueAdminStepUpToken({
    userId: adminId,
  });

  const cookieStore = await cookies();
  cookieStore.set(ADMIN_STEP_UP_COOKIE_NAME, issuedToken.token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: env.NODE_ENV === 'production',
    path: '/',
    expires: issuedToken.expiresAt,
  });

  await writeAdminActivityLog({
    adminId,
    actionType: 'ADMIN_STEP_UP_VERIFIED',
    targetType: 'AdminSession',
    targetEntityId: adminId,
    after: {
      method: challenge.method,
      expiresAt: issuedToken.expiresAt.toISOString(),
    },
  });

  redirect('/admin?stepUp=ok');
}

async function updateUserStatusAction(formData: FormData): Promise<void> {
  'use server';

  const adminId = await requireAdminUserId('users.manage');
  await ensureAdminStepUp(adminId);

  const parsedBody = adminUserStatusUpdateSchema.safeParse({
    userId: getFormString(formData, 'userId'),
    status: getFormString(formData, 'status'),
    isBlocked: getFormBoolean(formData, 'isBlocked'),
  });

  if (!parsedBody.success) {
    return;
  }

  if (
    parsedBody.data.userId === adminId &&
    (parsedBody.data.isBlocked || parsedBody.data.status !== 'ACTIVE')
  ) {
    return;
  }

  const beforeUser = await prisma.user.findUnique({
    where: {
      id: parsedBody.data.userId,
    },
    select: {
      id: true,
      email: true,
      status: true,
      isBlocked: true,
    },
  });

  if (!beforeUser) {
    return;
  }

  await prisma.user.update({
    where: {
      id: parsedBody.data.userId,
    },
    data: {
      status: parsedBody.data.status,
      isBlocked: parsedBody.data.isBlocked,
    },
  });

  if (parsedBody.data.status !== 'ACTIVE' || parsedBody.data.isBlocked) {
    await revokeAllUserSessions(
      parsedBody.data.userId,
      parsedBody.data.isBlocked ? 'ACCOUNT_BLOCKED' : 'ADMIN_REVOKED'
    );
  }

  const afterUser = await prisma.user.findUnique({
    where: {
      id: parsedBody.data.userId,
    },
    select: {
      id: true,
      email: true,
      status: true,
      isBlocked: true,
    },
  });

  await writeAdminActivityLog({
    adminId,
    actionType: 'USER_STATUS_UPDATED',
    targetType: 'User',
    targetEntityId: parsedBody.data.userId,
    before: beforeUser,
    after: afterUser,
  });

  revalidatePath('/admin');
}

async function assignRoleAction(formData: FormData): Promise<void> {
  'use server';

  const adminId = await requireAdminUserId('roles.assign');
  await ensureAdminStepUp(adminId);

  const parsedBody = adminAssignRoleSchema.safeParse({
    userId: getFormString(formData, 'userId'),
    roleName: getFormString(formData, 'roleName'),
  });

  if (!parsedBody.success) {
    return;
  }

  const beforeUser = await prisma.user.findUnique({
    where: {
      id: parsedBody.data.userId,
    },
    select: {
      id: true,
      email: true,
      roles: {
        where: {
          OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
        },
        select: {
          role: {
            select: {
              name: true,
            },
          },
        },
      },
    },
  });

  if (!beforeUser) {
    return;
  }

  await assignRoleToUser(parsedBody.data.userId, parsedBody.data.roleName, adminId);
  await revokeAllUserSessions(parsedBody.data.userId, 'ROLE_CHANGED');

  const afterUser = await prisma.user.findUnique({
    where: {
      id: parsedBody.data.userId,
    },
    select: {
      id: true,
      email: true,
      roles: {
        where: {
          OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
        },
        select: {
          role: {
            select: {
              name: true,
            },
          },
        },
      },
    },
  });

  await writeAdminActivityLog({
    adminId,
    actionType: 'ROLE_ASSIGNED',
    targetType: 'User',
    targetEntityId: parsedBody.data.userId,
    before: {
      roles: beforeUser.roles.map((row) => row.role.name),
    },
    after: {
      roles: afterUser?.roles.map((row) => row.role.name) ?? [],
      assignedRole: parsedBody.data.roleName,
    },
  });

  revalidatePath('/admin');
}

export default async function AdminPage({
  searchParams,
}: Readonly<{
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}>) {
  const params = await searchParams;
  const stepUpState = getSearchParam(params, 'stepUp');

  await requireAdminUserId('users.read');

  const [users, roles] = await Promise.all([
    prisma.user.findMany({
      select: {
        id: true,
        name: true,
        email: true,
        status: true,
        isBlocked: true,
        emailVerified: true,
        createdAt: true,
        roles: {
          where: {
            OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
          },
          select: {
            role: {
              select: {
                name: true,
              },
            },
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
      take: 100,
    }),
    prisma.role.findMany({
      select: {
        name: true,
      },
      orderBy: {
        name: 'asc',
      },
    }),
  ]);

  return (
    <main className='mx-auto w-full max-w-5xl p-6'>
      <p className='text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500'>
        Admin Console
      </p>
      <h1 className='mt-2 text-2xl font-semibold text-zinc-900 dark:text-zinc-100'>
        Security and Billing Control Center
      </h1>
      <p className='mt-3 text-sm text-zinc-600 dark:text-zinc-300'>
        Manage account state and roles from a secured admin surface. Every mutation writes an
        AdminActivityLog entry with before/after snapshots.
      </p>

      <section className='mt-6 rounded-2xl border border-black/10 bg-white/80 p-4 dark:border-white/10 dark:bg-zinc-950/80'>
        <p className='text-xs font-semibold uppercase tracking-[0.14em] text-zinc-500'>
          Step-Up Verification
        </p>
        <p className='mt-2 text-sm text-zinc-600 dark:text-zinc-300'>
          Confirm an MFA code before making sensitive admin changes.
        </p>

        {stepUpState === 'ok' ? (
          <p className='mt-3 rounded-lg border border-emerald-300/60 bg-emerald-100/70 px-3 py-2 text-xs text-emerald-900 dark:border-emerald-700/60 dark:bg-emerald-950/60 dark:text-emerald-200'>
            Step-up verified. Sensitive admin actions are temporarily unlocked.
          </p>
        ) : null}

        {stepUpState === 'required' ? (
          <p className='mt-3 rounded-lg border border-amber-300/60 bg-amber-100/70 px-3 py-2 text-xs text-amber-900 dark:border-amber-700/60 dark:bg-amber-950/60 dark:text-amber-200'>
            Step-up verification is required before changing account status or roles.
          </p>
        ) : null}

        {stepUpState === 'invalid' ? (
          <p className='mt-3 rounded-lg border border-rose-300/60 bg-rose-100/70 px-3 py-2 text-xs text-rose-900 dark:border-rose-700/60 dark:bg-rose-950/60 dark:text-rose-200'>
            Invalid MFA input. Try again with a valid authenticator or backup code.
          </p>
        ) : null}

        {stepUpState === 'enableMfa' ? (
          <p className='mt-3 rounded-lg border border-amber-300/60 bg-amber-100/70 px-3 py-2 text-xs text-amber-900 dark:border-amber-700/60 dark:bg-amber-950/60 dark:text-amber-200'>
            MFA must be enabled on your account before step-up verification can be used.
          </p>
        ) : null}

        <form action={verifyStepUpAction} className='mt-4 grid gap-2 sm:grid-cols-3'>
          <input
            name='stepUpCode'
            type='text'
            inputMode='numeric'
            autoComplete='one-time-code'
            placeholder='Authenticator code'
            className='rounded-lg border border-black/10 bg-white px-2 py-1 text-xs dark:border-white/20 dark:bg-zinc-950'
          />
          <input
            name='stepUpBackupCode'
            type='text'
            autoComplete='off'
            placeholder='Backup code (optional)'
            className='rounded-lg border border-black/10 bg-white px-2 py-1 text-xs dark:border-white/20 dark:bg-zinc-950'
          />
          <button
            type='submit'
            className='rounded-lg border border-black/10 bg-white px-2 py-1 text-xs font-medium transition hover:bg-zinc-50 dark:border-white/20 dark:bg-zinc-900 dark:hover:bg-zinc-800'
          >
            Verify step-up
          </button>
        </form>
      </section>

      <section className='mt-6 overflow-x-auto rounded-2xl border border-black/10 bg-white/80 p-4 dark:border-white/10 dark:bg-zinc-950/80'>
        <table className='min-w-full border-separate border-spacing-y-2 text-sm'>
          <thead>
            <tr className='text-left text-xs uppercase tracking-[0.14em] text-zinc-500'>
              <th className='px-2 py-1'>User</th>
              <th className='px-2 py-1'>Verification</th>
              <th className='px-2 py-1'>Roles</th>
              <th className='px-2 py-1'>Status Controls</th>
              <th className='px-2 py-1'>Role Assignment</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => {
              const roleNames = user.roles.map((entry) => entry.role.name);

              return (
                <tr key={user.id} className='align-top'>
                  <td className='rounded-l-xl bg-zinc-100 px-2 py-2 dark:bg-zinc-900'>
                    <p className='font-medium text-zinc-900 dark:text-zinc-100'>
                      {user.name ?? 'Unnamed User'}
                    </p>
                    <p className='text-xs text-zinc-600 dark:text-zinc-400'>{user.email}</p>
                    <p className='text-xs text-zinc-500'>
                      Joined{' '}
                      {new Intl.DateTimeFormat('en-US', { dateStyle: 'medium' }).format(
                        user.createdAt
                      )}
                    </p>
                  </td>
                  <td className='bg-zinc-100 px-2 py-2 dark:bg-zinc-900'>
                    <p className='text-xs text-zinc-700 dark:text-zinc-300'>
                      {user.emailVerified ? 'Verified' : 'Unverified'}
                    </p>
                    <p className='text-xs text-zinc-500'>
                      {user.emailVerified
                        ? new Intl.DateTimeFormat('en-US', { dateStyle: 'medium' }).format(
                            user.emailVerified
                          )
                        : 'Awaiting verification'}
                    </p>
                  </td>
                  <td className='bg-zinc-100 px-2 py-2 dark:bg-zinc-900'>
                    <p className='text-xs text-zinc-700 dark:text-zinc-300'>
                      {roleNames.length > 0 ? roleNames.join(', ') : 'No active roles'}
                    </p>
                  </td>
                  <td className='bg-zinc-100 px-2 py-2 dark:bg-zinc-900'>
                    <form action={updateUserStatusAction} className='grid gap-2'>
                      <input type='hidden' name='userId' value={user.id} />
                      <select
                        name='status'
                        defaultValue={user.status}
                        className='rounded-lg border border-black/10 bg-white px-2 py-1 text-xs dark:border-white/20 dark:bg-zinc-950'
                      >
                        <option value='ACTIVE'>ACTIVE</option>
                        <option value='SUSPENDED'>SUSPENDED</option>
                        <option value='DELETED'>DELETED</option>
                      </select>
                      <label className='inline-flex items-center gap-2 text-xs text-zinc-600 dark:text-zinc-300'>
                        <input
                          type='checkbox'
                          name='isBlocked'
                          value='true'
                          defaultChecked={user.isBlocked}
                          className='size-3.5 rounded border border-black/20 dark:border-white/30'
                        />
                        <span>Block account</span>
                      </label>
                      <button
                        type='submit'
                        className='rounded-lg border border-black/10 bg-white px-2 py-1 text-xs font-medium transition hover:bg-zinc-50 dark:border-white/20 dark:bg-zinc-900 dark:hover:bg-zinc-800'
                      >
                        Save status
                      </button>
                    </form>
                  </td>
                  <td className='rounded-r-xl bg-zinc-100 px-2 py-2 dark:bg-zinc-900'>
                    <form action={assignRoleAction} className='grid gap-2'>
                      <input type='hidden' name='userId' value={user.id} />
                      <select
                        name='roleName'
                        defaultValue={roles[0]?.name ?? 'USER'}
                        className='rounded-lg border border-black/10 bg-white px-2 py-1 text-xs dark:border-white/20 dark:bg-zinc-950'
                      >
                        {roles.map((role) => (
                          <option key={`${user.id}-${role.name}`} value={role.name}>
                            {role.name}
                          </option>
                        ))}
                      </select>
                      <button
                        type='submit'
                        className='rounded-lg border border-black/10 bg-white px-2 py-1 text-xs font-medium transition hover:bg-zinc-50 dark:border-white/20 dark:bg-zinc-900 dark:hover:bg-zinc-800'
                      >
                        Assign role
                      </button>
                    </form>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
    </main>
  );
}
