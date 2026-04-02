import { auth } from '@/auth';
import { adminIpAllowlist } from '@/lib/env';
import { logger } from '@/lib/logger';
import { isSessionActive, SESSION_COOKIE_NAMES } from '@/lib/security/session-revocation';
import { NextResponse, type NextRequest } from 'next/server';

const ADMIN_ROLES = new Set(['SUPER_ADMIN', 'ADMIN']);
const PROTECTED_PREFIXES = ['/dashboard', '/admin'] as const;

function buildCspValue(nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' https://api.lemonsqueezy.com https://*.lemonsqueezy.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ');
}

function createNonce(): string {
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);
  return Array.from(randomBytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function clientIp(request: NextRequest): string | null {
  const forwardedFor = request.headers.get('x-forwarded-for');

  if (forwardedFor) {
    return forwardedFor.split(',')[0]?.trim() ?? null;
  }

  return request.headers.get('x-real-ip');
}

function getSessionToken(request: NextRequest): string {
  for (const cookieName of SESSION_COOKIE_NAMES) {
    const token = request.cookies.get(cookieName)?.value;

    if (token) {
      return token;
    }
  }

  return '';
}

function isProtectedPath(pathname: string): boolean {
  return PROTECTED_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

function isAdminPath(pathname: string): boolean {
  return pathname.startsWith('/admin');
}

function withSecurityHeaders(response: NextResponse, nonce: string): NextResponse {
  response.headers.set('Content-Security-Policy', buildCspValue(nonce));
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  response.headers.set('x-csp-nonce', nonce);

  return response;
}

function nextWithSecurityHeaders(request: NextRequest, nonce: string): NextResponse {
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-csp-nonce', nonce);

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });

  return withSecurityHeaders(response, nonce);
}

function notFoundResponse(nonce: string): NextResponse {
  return withSecurityHeaders(new NextResponse(null, { status: 404 }), nonce);
}

function signInRedirectResponse(request: NextRequest, nonce: string): NextResponse {
  const signInUrl = new URL('/login', request.nextUrl);
  signInUrl.searchParams.set('callbackUrl', request.nextUrl.pathname);
  return withSecurityHeaders(NextResponse.redirect(signInUrl), nonce);
}

function protectedDenyResponse(
  request: NextRequest,
  nonce: string,
  pathname: string
): NextResponse {
  return isAdminPath(pathname) ? notFoundResponse(nonce) : signInRedirectResponse(request, nonce);
}

function hasAdminRole(roles: string[]): boolean {
  return roles.some((role) => ADMIN_ROLES.has(role));
}

function isAllowedAdminIp(request: NextRequest, pathname: string): boolean {
  if (adminIpAllowlist.length === 0) {
    return true;
  }

  const requestIp = clientIp(request);

  if (!requestIp || !adminIpAllowlist.includes(requestIp)) {
    logger.warn('admin.access.ip_denied', {
      path: pathname,
      ip: requestIp ?? 'unknown',
    });
    return false;
  }

  return true;
}

async function resolveProtectedAccessDenial(
  request: NextRequest,
  session:
    | {
        user?: {
          isBlocked: boolean;
          status: string;
          roles: string[];
        };
      }
    | null
    | undefined,
  pathname: string
): Promise<'allow' | 'deny'> {
  const sessionToken = getSessionToken(request);

  if (!session?.user || !sessionToken) {
    return 'deny';
  }

  const hasActiveSession = await isSessionActive(sessionToken);

  if (!hasActiveSession) {
    return 'deny';
  }

  if (session.user.isBlocked || session.user.status !== 'ACTIVE') {
    return 'deny';
  }

  if (!isAdminPath(pathname)) {
    return 'allow';
  }

  if (!isAllowedAdminIp(request, pathname)) {
    return 'deny';
  }

  if (!hasAdminRole(session.user.roles)) {
    return 'deny';
  }

  return 'allow';
}

export default auth(async (request) => {
  const nonce = createNonce();
  const pathname = request.nextUrl.pathname;

  if (!isProtectedPath(pathname)) {
    return nextWithSecurityHeaders(request, nonce);
  }

  const accessResult = await resolveProtectedAccessDenial(request, request.auth, pathname);

  if (accessResult === 'deny') {
    return protectedDenyResponse(request, nonce, pathname);
  }

  return nextWithSecurityHeaders(request, nonce);
});

export const config = {
  matcher: ['/((?!api/auth|_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml).*)'],
};
