import { z } from 'zod';

const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(320)
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Invalid email address');

export const credentialsSignInSchema = z.object({
  email: emailSchema,
  password: z.string().min(8).max(128),
  mfaCode: z.string().trim().min(6).max(12).optional(),
  backupCode: z.string().trim().min(6).max(32).optional(),
});

export const registerUserSchema = z.object({
  name: z.string().min(2).max(100),
  email: emailSchema,
  password: z.string().min(12).max(128),
});

export const verifyEmailSchema = z.object({
  email: emailSchema,
  token: z.string().min(16).max(512),
});

export const requestPasswordResetSchema = z.object({
  email: emailSchema,
});

export const completePasswordResetSchema = z.object({
  email: emailSchema,
  token: z.string().min(16).max(512),
  password: z.string().min(12).max(128),
});

export const revokeSessionSchema = z.object({
  scope: z.enum(['current', 'all']).default('current'),
});

export const resetPasswordSearchParamsSchema = z.object({
  email: z.string().optional(),
  token: z.string().optional(),
});

export const mfaEnrollStartSchema = z.object({
  password: z.string().min(8).max(128),
});

export const mfaEnrollVerifySchema = z.object({
  code: z.string().trim().min(6).max(12),
});

export const mfaChallengeSchema = z
  .object({
    code: z.string().trim().min(6).max(12).optional(),
    backupCode: z.string().trim().min(6).max(32).optional(),
  })
  .refine((value) => Boolean(value.code || value.backupCode), {
    message: 'Either code or backupCode is required',
    path: ['code'],
  });
