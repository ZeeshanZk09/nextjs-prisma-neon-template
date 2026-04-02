import { auth } from '@/auth';
import {
  SESSION_COOKIE_NAMES,
  revokeAllUserSessions,
  revokeSessionByToken,
} from '@/lib/security/session-revocation';
import { revokeSessionSchema } from '@/lib/validations/auth';

export async function POST(request: Request): Promise<Response> {
  const session = await auth();

  if (!session?.user?.id) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const jsonBody = (await request.json().catch(() => ({}))) as unknown;
  const parsedBody = revokeSessionSchema.safeParse(jsonBody);

  if (!parsedBody.success) {
    return Response.json({ error: 'Invalid revoke payload' }, { status: 400 });
  }

  if (parsedBody.data.scope === 'all') {
    await revokeAllUserSessions(session.user.id, 'USER_LOGOUT');
    return Response.json({ ok: true, scope: 'all' });
  }

  const cookieHeader = request.headers.get('cookie') ?? '';
  let currentToken = '';

  for (const cookieName of SESSION_COOKIE_NAMES) {
    const cookiePattern = new RegExp(`(?:^|; )${cookieName}=([^;]+)`);
    const match = cookiePattern.exec(cookieHeader);
    if (match?.[1]) {
      currentToken = decodeURIComponent(match[1]);
      break;
    }
  }

  if (!currentToken) {
    return Response.json({ ok: true, scope: 'current', revoked: 0 });
  }

  const revoked = await revokeSessionByToken(currentToken, 'USER_LOGOUT');

  return Response.json({ ok: true, scope: 'current', revoked });
}
