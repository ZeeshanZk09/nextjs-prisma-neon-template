import { registerUserFlow } from '@/lib/auth/workflows';
import { getClientIpFromRequest } from '@/lib/http/request';
import { cleanupRateLimitBuckets, rateLimit } from '@/lib/security/rate-limit';
import { registerUserSchema } from '@/lib/validations/auth';

const REGISTER_IP_LIMIT = 10;
const REGISTER_EMAIL_LIMIT = 5;
const REGISTER_WINDOW_MS = 1000 * 60 * 15;

export async function POST(request: Request): Promise<Response> {
  cleanupRateLimitBuckets();

  const ipAddress = getClientIpFromRequest(request) ?? 'unknown';
  const ipBucket = rateLimit(
    `auth:register:ip:${ipAddress}`,
    REGISTER_IP_LIMIT,
    REGISTER_WINDOW_MS
  );

  if (!ipBucket.allowed) {
    const retryAfter = Math.max(1, Math.ceil((ipBucket.resetAt - Date.now()) / 1000));
    return Response.json(
      { error: 'Too many registration attempts' },
      { status: 429, headers: { 'Retry-After': `${retryAfter}` } }
    );
  }

  const requestBody = (await request.json().catch(() => ({}))) as unknown;
  const parsedBody = registerUserSchema.safeParse(requestBody);

  if (!parsedBody.success) {
    return Response.json({ error: 'Invalid registration payload' }, { status: 400 });
  }

  const emailBucket = rateLimit(
    `auth:register:email:${parsedBody.data.email}`,
    REGISTER_EMAIL_LIMIT,
    REGISTER_WINDOW_MS
  );

  if (!emailBucket.allowed) {
    const retryAfter = Math.max(1, Math.ceil((emailBucket.resetAt - Date.now()) / 1000));
    return Response.json(
      { error: 'Too many registration attempts' },
      { status: 429, headers: { 'Retry-After': `${retryAfter}` } }
    );
  }

  await registerUserFlow({
    name: parsedBody.data.name,
    email: parsedBody.data.email,
    password: parsedBody.data.password,
    requestedIp: ipAddress,
  });

  return Response.json({
    ok: true,
    message: 'If the account can be registered, verification instructions were sent.',
  });
}
