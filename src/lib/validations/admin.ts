import { z } from 'zod';

export const adminUserStatusUpdateSchema = z.object({
  userId: z.string().cuid(),
  status: z.enum(['ACTIVE', 'SUSPENDED', 'DELETED']),
  isBlocked: z.boolean(),
});

export const adminAssignRoleSchema = z.object({
  userId: z.string().cuid(),
  roleName: z
    .string()
    .trim()
    .min(2)
    .max(80)
    .regex(/^[A-Z_]+$/, 'Invalid role name format'),
});
