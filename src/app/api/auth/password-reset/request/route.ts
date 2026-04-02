import { requestPasswordResetFlow } from '@/lib/auth/workflows';
import { getClientIpFromRequest } from '@/lib/http/request';
import { cleanupRateLimitBuckets, rateLimit } from '@/lib/security/rate-limit';
import { requestPasswordResetSchema } from '@/lib/validations/auth';

const PASSWORD_RESET_IP_LIMIT = 10;
const PASSWORD_RESET_EMAIL_LIMIT = 4;
const PASSWORD_RESET_WINDOW_MS = 1000 * 60 * 15;

export async function POST(request: Request): Promise<Response> {
  cleanupRateLimitBuckets();

  const ipAddress = getClientIpFromRequest(request) ?? 'unknown';
  const ipBucket = rateLimit(
    `auth:password-reset-request:ip:${ipAddress}`,
    PASSWORD_RESET_IP_LIMIT,
    PASSWORD_RESET_WINDOW_MS
  );

  if (!ipBucket.allowed) {
    const retryAfter = Math.max(1, Math.ceil((ipBucket.resetAt - Date.now()) / 1000));
    return Response.json(
      { error: 'Too many reset requests' },
      { status: 429, headers: { 'Retry-After': `${retryAfter}` } }
    );
  }

  const requestBody = (await request.json().catch(() => ({}))) as unknown;
  const parsedBody = requestPasswordResetSchema.safeParse(requestBody);

  if (!parsedBody.success) {
    return Response.json({ error: 'Invalid request payload' }, { status: 400 });
  }

  const emailBucket = rateLimit(
    `auth:password-reset-request:email:${parsedBody.data.email}`,
    PASSWORD_RESET_EMAIL_LIMIT,
    PASSWORD_RESET_WINDOW_MS
  );

  if (!emailBucket.allowed) {
    const retryAfter = Math.max(1, Math.ceil((emailBucket.resetAt - Date.now()) / 1000));
    return Response.json(
      { error: 'Too many reset requests' },
      { status: 429, headers: { 'Retry-After': `${retryAfter}` } }
    );
  }

  await requestPasswordResetFlow({
    email: parsedBody.data.email,
    requestedIp: ipAddress,
  });

  return Response.json({
    ok: true,
    message: 'If the account exists, a reset email was sent.',
  });
}
