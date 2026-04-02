import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  AUTH_SECRET: z.string().min(32, 'AUTH_SECRET must be at least 32 characters'),
  NEXT_PUBLIC_APP_URL: z
    .string()
    .trim()
    .regex(/^https?:\/\/[^\s]+$/i, 'NEXT_PUBLIC_APP_URL must be a valid URL'),
  AUTH_GOOGLE_ID: z.string().optional(),
  AUTH_GOOGLE_SECRET: z.string().optional(),
  AUTH_GITHUB_ID: z.string().optional(),
  AUTH_GITHUB_SECRET: z.string().optional(),
  AUTH_PASSWORD_PEPPER: z.string().optional(),
  MFA_ENCRYPTION_KEY: z.string().optional(),
  ADMIN_STEP_UP_TTL_SECONDS: z.string().optional(),
  LEMONSQUEEZY_API_KEY: z.string().optional(),
  LEMONSQUEEZY_STORE_ID: z.string().optional(),
  LEMONSQUEEZY_WEBHOOK_SECRET: z.string().optional(),
  BOOTSTRAP_SUPER_ADMIN_EMAIL: z.string().optional(),
  BOOTSTRAP_SUPER_ADMIN_NAME: z.string().optional(),
  BOOTSTRAP_SUPER_ADMIN_PASSWORD: z.string().optional(),
  ADMIN_IP_ALLOWLIST: z.string().optional(),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  ENABLE_HIBP_PASSWORD_CHECK: z.string().optional(),
});

const parsedEnv = envSchema.safeParse({
  NODE_ENV: process.env.NODE_ENV,
  DATABASE_URL: process.env.DATABASE_URL,
  AUTH_SECRET: process.env.AUTH_SECRET,
  NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL,
  AUTH_GOOGLE_ID: process.env.AUTH_GOOGLE_ID,
  AUTH_GOOGLE_SECRET: process.env.AUTH_GOOGLE_SECRET,
  AUTH_GITHUB_ID: process.env.AUTH_GITHUB_ID,
  AUTH_GITHUB_SECRET: process.env.AUTH_GITHUB_SECRET,
  AUTH_PASSWORD_PEPPER: process.env.AUTH_PASSWORD_PEPPER,
  MFA_ENCRYPTION_KEY: process.env.MFA_ENCRYPTION_KEY,
  ADMIN_STEP_UP_TTL_SECONDS: process.env.ADMIN_STEP_UP_TTL_SECONDS,
  LEMONSQUEEZY_API_KEY: process.env.LEMONSQUEEZY_API_KEY,
  LEMONSQUEEZY_STORE_ID: process.env.LEMONSQUEEZY_STORE_ID,
  LEMONSQUEEZY_WEBHOOK_SECRET: process.env.LEMONSQUEEZY_WEBHOOK_SECRET,
  BOOTSTRAP_SUPER_ADMIN_EMAIL: process.env.BOOTSTRAP_SUPER_ADMIN_EMAIL,
  BOOTSTRAP_SUPER_ADMIN_NAME: process.env.BOOTSTRAP_SUPER_ADMIN_NAME,
  BOOTSTRAP_SUPER_ADMIN_PASSWORD: process.env.BOOTSTRAP_SUPER_ADMIN_PASSWORD,
  ADMIN_IP_ALLOWLIST: process.env.ADMIN_IP_ALLOWLIST,
  LOG_LEVEL: process.env.LOG_LEVEL,
  ENABLE_HIBP_PASSWORD_CHECK: process.env.ENABLE_HIBP_PASSWORD_CHECK,
});

if (!parsedEnv.success) {
  const issueList = parsedEnv.error.issues
    .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
    .join('; ');

  throw new Error(`Invalid environment configuration: ${issueList}`);
}

export const env = parsedEnv.data;

export const adminIpAllowlist = (env.ADMIN_IP_ALLOWLIST ?? '')
  .split(',')
  .map((entry) => entry.trim())
  .filter(Boolean);

export const isHibpPasswordCheckEnabled =
  (env.ENABLE_HIBP_PASSWORD_CHECK ?? 'true').toLowerCase() !== 'false';

export const adminStepUpTtlSeconds = (() => {
  const raw = env.ADMIN_STEP_UP_TTL_SECONDS;

  if (!raw) {
    return 600;
  }

  const parsed = Number.parseInt(raw, 10);

  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 600;
  }

  return Math.min(parsed, 3600);
})();
