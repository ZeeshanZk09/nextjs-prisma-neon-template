import { env } from '@/lib/env';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

type LogContext = {
  userId?: string;
  requestId?: string;
  ip?: string;
  path?: string;
  durationMs?: number;
  [key: string]: unknown;
};

const levelWeight: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const secretRegexPatterns = [
  /sk_[A-Za-z0-9_-]+/g,
  /whsec_[A-Za-z0-9_-]+/g,
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,
];

const knownSecretValues = [
  env.AUTH_SECRET,
  env.AUTH_PASSWORD_PEPPER,
  env.AUTH_GOOGLE_SECRET,
  env.AUTH_GITHUB_SECRET,
  env.LEMONSQUEEZY_API_KEY,
  env.LEMONSQUEEZY_WEBHOOK_SECRET,
  env.BOOTSTRAP_SUPER_ADMIN_PASSWORD,
].filter((value): value is string => Boolean(value));

function shouldLog(level: LogLevel): boolean {
  return levelWeight[level] >= levelWeight[env.LOG_LEVEL];
}

function redactString(value: string): string {
  let redacted = value;

  for (const pattern of secretRegexPatterns) {
    redacted = redacted.replace(pattern, '[REDACTED]');
  }

  for (const secretValue of knownSecretValues) {
    if (secretValue.length > 0) {
      redacted = redacted.split(secretValue).join('[REDACTED]');
    }
  }

  return redacted;
}

function redactValue(value: unknown): unknown {
  if (typeof value === 'string') {
    return redactString(value);
  }

  if (Array.isArray(value)) {
    return value.map((entry) => redactValue(entry));
  }

  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};

    for (const [key, nestedValue] of Object.entries(value)) {
      if (/password|secret|token|key/i.test(key)) {
        output[key] = '[REDACTED]';
      } else {
        output[key] = redactValue(nestedValue);
      }
    }

    return output;
  }

  return value;
}

function writeLog(level: LogLevel, message: string, context: LogContext = {}): void {
  if (!shouldLog(level)) {
    return;
  }

  const logRecord = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...context,
  };

  const payload = JSON.stringify(redactValue(logRecord));

  if (level === 'error') {
    console.error(payload);
    return;
  }

  if (level === 'warn') {
    console.warn(payload);
    return;
  }

  if (level === 'debug') {
    console.debug(payload);
    return;
  }

  console.info(payload);
}

export const logger = {
  debug(message: string, context?: LogContext) {
    writeLog('debug', message, context);
  },
  info(message: string, context?: LogContext) {
    writeLog('info', message, context);
  },
  warn(message: string, context?: LogContext) {
    writeLog('warn', message, context);
  },
  error(message: string, context?: LogContext) {
    writeLog('error', message, context);
  },
};
