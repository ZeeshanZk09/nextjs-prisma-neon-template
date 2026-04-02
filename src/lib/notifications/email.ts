import { logger } from '@/lib/logger';
import { env } from '@/lib/env';
import nodemailer from 'nodemailer';
import type { SendMailOptions, Transporter } from 'nodemailer';
import type SMTPTransport from 'nodemailer/lib/smtp-transport';

type TransactionalEmail = {
  to: string;
  subject: string;
  text: string;
  html?: string;
  from?: string;
  replyTo?: string;
};

type MailProvider = 'gmail' | 'smtp';

type MailConfig = {
  provider: MailProvider;
  user: string;
  pass: string;
  from: string;
  fromName: string;
  host?: string;
  port?: number;
  secure?: boolean;
};

const DEFAULT_SMTP_PORT = 587;
const DEFAULT_FROM_NAME = 'Zebotix';

declare global {
  var emailTransporter: Transporter | undefined;
}

function parseBooleanFlag(value: string | undefined): boolean {
  const normalized = value?.trim().toLowerCase();
  return normalized === 'true' || normalized === '1' || normalized === 'yes';
}

function resolveProvider(host: string | undefined): MailProvider {
  const rawProvider = env.SMTP_PROVIDER?.trim().toLowerCase();

  if (rawProvider === 'smtp' || rawProvider === 'gmail') {
    return rawProvider;
  }

  if (host) {
    return 'smtp';
  }

  return 'gmail';
}

function resolveMailConfig(): MailConfig | null {
  const host = env.SMTP_HOST?.trim() || undefined;
  const user = env.SMTP_USER?.trim();
  const pass = env.SMTP_PASS;
  const from = env.SMTP_FROM?.trim() || user;
  const provider = resolveProvider(host);

  if (!user || !pass || !from) {
    return null;
  }

  if (provider === 'smtp') {
    if (!host) {
      return null;
    }

    const parsedPort = Number.parseInt(env.SMTP_PORT ?? '', 10);
    const port = Number.isFinite(parsedPort) && parsedPort > 0 ? parsedPort : DEFAULT_SMTP_PORT;

    return {
      provider,
      host,
      port,
      secure: parseBooleanFlag(env.SMTP_SECURE),
      user,
      pass,
      from,
      fromName: env.SMTP_FROM_NAME?.trim() || DEFAULT_FROM_NAME,
    };
  }

  return {
    provider,
    user,
    pass,
    from,
    fromName: env.SMTP_FROM_NAME?.trim() || DEFAULT_FROM_NAME,
  };
}

function buildTransportOptions(config: MailConfig): SMTPTransport.Options {
  if (config.provider === 'gmail') {
    return {
      service: 'gmail',
      auth: {
        user: config.user,
        pass: config.pass,
      },
    };
  }

  return {
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: {
      user: config.user,
      pass: config.pass,
    },
  };
}

function getOrCreateTransporter(config: MailConfig): Transporter {
  const transporter = (global.emailTransporter ??= nodemailer.createTransport({
    ...buildTransportOptions(config),
  }));

  return transporter;
}

function unconfiguredSmtpMessage(): string {
  return 'Email transport is not configured. For Gmail set SMTP_USER/SMTP_PASS (optional SMTP_FROM). For custom SMTP set SMTP_PROVIDER=smtp and provide SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS.';
}

export async function sendTransactionalEmail(payload: TransactionalEmail): Promise<void> {
  const config = resolveMailConfig();

  if (!config) {
    const message = unconfiguredSmtpMessage();

    if (env.NODE_ENV === 'production') {
      logger.error('email.smtp.unconfigured', {
        to: payload.to,
        subject: payload.subject,
      });

      throw new Error(message);
    }

    logger.warn('email.smtp.unconfigured_dev', {
      to: payload.to,
      subject: payload.subject,
      hint: message,
    });
    return;
  }

  const transporter = getOrCreateTransporter(config);

  const mailOptions: SendMailOptions = {
    from: payload.from ?? `${config.fromName} <${config.from}>`,
    to: payload.to,
    subject: payload.subject,
    text: payload.text,
    html: payload.html,
    replyTo: payload.replyTo,
  };

  try {
    const result = await transporter.sendMail(mailOptions);

    logger.info('email.smtp.sent', {
      provider: config.provider,
      to: payload.to,
      subject: payload.subject,
      messageId: result.messageId,
      accepted: result.accepted.length,
      rejected: result.rejected.length,
      response: result.response,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown SMTP error';

    logger.error('email.smtp.send_failed', {
      to: payload.to,
      subject: payload.subject,
      error: message,
    });

    throw new Error(`Email delivery failed: ${message}`);
  }
}
