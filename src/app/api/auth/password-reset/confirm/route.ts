import { resetPasswordFlow } from '@/lib/auth/workflows';
import { getClientIpFromRequest } from '@/lib/http/request';
import { cleanupRateLimitBuckets, rateLimit } from '@/lib/security/rate-limit';
import { completePasswordResetSchema } from '@/lib/validations/auth';

const PASSWORD_RESET_CONFIRM_LIMIT = 6;
const PASSWORD_RESET_CONFIRM_WINDOW_MS = 1000 * 60 * 15;

export async function POST(request: Request): Promise<Response> {
  cleanupRateLimitBuckets();

  const ipAddress = getClientIpFromRequest(request) ?? 'unknown';
  const ipBucket = rateLimit(
    `auth:password-reset-confirm:ip:${ipAddress}`,
    PASSWORD_RESET_CONFIRM_LIMIT,
    PASSWORD_RESET_CONFIRM_WINDOW_MS
  );

  if (!ipBucket.allowed) {
    const retryAfter = Math.max(1, Math.ceil((ipBucket.resetAt - Date.now()) / 1000));
    return Response.json(
      { error: 'Too many reset attempts' },
      { status: 429, headers: { 'Retry-After': `${retryAfter}` } }
    );
  }

  const requestBody = (await request.json().catch(() => ({}))) as unknown;
  const parsedBody = completePasswordResetSchema.safeParse(requestBody);

  if (!parsedBody.success) {
    return Response.json({ error: 'Invalid reset payload' }, { status: 400 });
  }

  const reset = await resetPasswordFlow({
    email: parsedBody.data.email,
    token: parsedBody.data.token,
    password: parsedBody.data.password,
  });

  if (!reset) {
    return Response.json({ error: 'Invalid or expired reset token' }, { status: 400 });
  }

  return Response.json({ ok: true });
}
