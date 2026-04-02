import { verifyEmailFlow } from '@/lib/auth/workflows';
import { verifyEmailSchema } from '@/lib/validations/auth';

const LOGIN_PATH = '/login';

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const email = url.searchParams.get('email') ?? '';
  const token = url.searchParams.get('token') ?? '';

  const parsedInput = verifyEmailSchema.safeParse({ email, token });

  const loginUrl = new URL(LOGIN_PATH, request.url);

  if (!parsedInput.success) {
    loginUrl.searchParams.set('verifyError', '1');
    return Response.redirect(loginUrl, 302);
  }

  const verified = await verifyEmailFlow(parsedInput.data);
  loginUrl.searchParams.set(verified ? 'verified' : 'verifyError', '1');
  return Response.redirect(loginUrl, 302);
}

export async function POST(request: Request): Promise<Response> {
  const requestBody = (await request.json().catch(() => ({}))) as unknown;
  const parsedBody = verifyEmailSchema.safeParse(requestBody);

  if (!parsedBody.success) {
    return Response.json({ error: 'Invalid verification payload' }, { status: 400 });
  }

  const verified = await verifyEmailFlow(parsedBody.data);

  if (!verified) {
    return Response.json({ error: 'Invalid or expired verification token' }, { status: 400 });
  }

  return Response.json({ ok: true });
}
