import { randomUUID } from 'node:crypto';

import { headers } from 'next/headers';

import type { Prisma } from '@/lib/generated/prisma/client';
import prisma from '@/lib/prisma';

type AdminActivityInput = {
  adminId: string;
  actionType: string;
  targetType?: string | null;
  targetEntityId?: string | null;
  before?: unknown;
  after?: unknown;
  requestId?: string;
  ipAddress?: string | null;
  userAgent?: string | null;
};

function toSnapshot(value: unknown): Prisma.InputJsonValue | undefined {
  if (value === null || value === undefined) {
    return undefined;
  }

  const clonedValue = structuredClone(value);

  if (clonedValue instanceof Date) {
    return clonedValue.toISOString();
  }

  return clonedValue as Prisma.InputJsonValue;
}

function resolveForwardedIp(headerValue: string | null): string | null {
  if (!headerValue) {
    return null;
  }

  return headerValue.split(',')[0]?.trim() ?? null;
}

export async function writeAdminActivityLog(input: AdminActivityInput): Promise<void> {
  let ipAddress = input.ipAddress ?? null;
  let userAgent = input.userAgent ?? null;

  if (!ipAddress || !userAgent) {
    try {
      const requestHeaders = await headers();

      if (!ipAddress) {
        ipAddress =
          resolveForwardedIp(requestHeaders.get('x-forwarded-for')) ??
          requestHeaders.get('x-real-ip') ??
          null;
      }

      if (!userAgent) {
        userAgent = requestHeaders.get('user-agent');
      }
    } catch {
      // If headers are unavailable in the current execution context, keep null values.
    }
  }

  await prisma.adminActivityLog.create({
    data: {
      adminId: input.adminId,
      actionType: input.actionType,
      targetType: input.targetType ?? null,
      targetEntityId: input.targetEntityId ?? null,
      before: toSnapshot(input.before),
      after: toSnapshot(input.after),
      requestId: input.requestId ?? randomUUID(),
      ipAddress,
      userAgent,
    },
  });
}
