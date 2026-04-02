export function getClientIpFromRequest(request: Request): string | null {
  const forwardedFor = request.headers.get('x-forwarded-for');

  if (forwardedFor) {
    return forwardedFor.split(',')[0]?.trim() ?? null;
  }

  const realIp = request.headers.get('x-real-ip');
  return realIp?.trim() ?? null;
}

export function getUserAgentFromRequest(request: Request): string | null {
  return request.headers.get('user-agent');
}
