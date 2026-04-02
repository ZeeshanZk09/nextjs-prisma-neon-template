# Resellify Starter (Security-First Iteration 2)

Next.js + Prisma + Neon starter with a security-first implementation slice of:

- Auth.js (credentials + optional OAuth)
- Database-backed sessions
- Backend session revocation endpoint
- Role-aware route protection for dashboard/admin
- Security-hardened schema for Auth, RBAC, Billing, Logs, Settings
- Theme foundation (light/dark/system)
- Registration + email verification + password reset
- TOTP MFA enrollment + backup recovery codes
- LemonSqueezy webhook verification + idempotent processing
- Admin user management actions with append-only activity logs
- MFA step-up verification for sensitive admin mutations

## Stack

- Next.js 16 (App Router)
- Prisma ORM + PostgreSQL (Neon)
- Auth.js v5 beta
- Tailwind CSS
- next-themes

## Iteration 2 Scope

- Hardened Prisma schema with models for:
  - User/Auth
  - Roles/Permissions
  - Plans/Subscriptions/Invoices
  - Notifications, Audit logs, System logs
  - User and app settings
- Auth routes configured at:
  - /api/auth/[...nextauth]
  - /api/auth/register
  - /api/auth/verify-email
  - /api/auth/password-reset/request
  - /api/auth/password-reset/confirm
  - /api/auth/mfa/status
  - /api/auth/mfa/enroll/start
  - /api/auth/mfa/enroll/verify
  - /api/auth/mfa/disable
  - /api/auth/mfa/step-up
- Session revocation API configured at:
  - /api/auth/revoke
- Billing webhook configured at:
  - /api/webhooks/lemonsqueezy
- Protected route boundaries configured in:
  - /dashboard/\*
  - /admin/\*

## Security Baseline

- Centralized environment validation at app startup via src/lib/env.ts.
- Structured logging with secret scrubbing via src/lib/logger.ts.
- CSP nonce + global security headers applied in src/proxy.ts.
- Permission checks for admin actions via src/lib/auth/permissions.ts.
- Password hardening with Argon2 + zxcvbn + HIBP k-anonymity checks.
- TOTP MFA secrets encrypted at rest with step-up challenge tokens for admin actions.

## Environment

Environment variables are defined in .env.example.

Minimum required values:

- DATABASE_URL
- AUTH_SECRET
- NEXT_PUBLIC_APP_URL

Optional values:

- AUTH_GOOGLE_ID
- AUTH_GOOGLE_SECRET
- AUTH_GITHUB_ID
- AUTH_GITHUB_SECRET
- AUTH_PASSWORD_PEPPER
- MFA_ENCRYPTION_KEY
- ADMIN_STEP_UP_TTL_SECONDS
- ADMIN_IP_ALLOWLIST
- LOG_LEVEL
- ENABLE_HIBP_PASSWORD_CHECK
- LEMONSQUEEZY_API_KEY
- LEMONSQUEEZY_STORE_ID
- LEMONSQUEEZY_WEBHOOK_SECRET
- BOOTSTRAP_SUPER_ADMIN_EMAIL
- BOOTSTRAP_SUPER_ADMIN_NAME
- BOOTSTRAP_SUPER_ADMIN_PASSWORD

## Local Setup

1. Install dependencies

```bash
npm install
```

1. Generate Prisma client

```bash
npm run prisma:generate
```

1. Create and apply migrations

```bash
npm run prisma:migrate:dev -- --name init_security_foundation
```

1. Seed roles, permissions, and optional first SUPER_ADMIN

```bash
npm run seed:rbac
```

1. Run development server

```bash
npm run dev
```

## Secret Rotation

Rotate secrets independently with no source changes:

1. Rotate AUTH_SECRET and redeploy.
1. Rotate LEMONSQUEEZY_WEBHOOK_SECRET and update LemonSqueezy webhook settings.
1. Rotate DATABASE_URL credentials in Neon and update deployment environment variables.
1. Re-run smoke tests for login, session revocation, and webhook processing.

## Security Notes

- Credentials sign-in has lockout behavior after repeated failed attempts.
- Accounts with MFA enabled require either a valid TOTP code or a backup code at sign-in.
- Session records can be revoked from the backend via /api/auth/revoke.
- Admin route access is denied unless an admin role exists in the session.
- Destructive admin actions require a recent MFA step-up verification.
- Sensitive actions are modeled for auditability with AdminActivityLog/AuditLog/SystemLog.

## Next Iterations

- Upstash Redis rate limiting in production (replace in-memory limiter)
- Security events table + alerting pipeline
