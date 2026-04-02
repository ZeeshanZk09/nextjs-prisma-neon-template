import { logger } from '@/lib/logger';

type TransactionalEmail = {
  to: string;
  subject: string;
  text: string;
};

export async function sendTransactionalEmail(payload: TransactionalEmail): Promise<void> {
  // In iteration 2 we keep a safe no-op transport for production unless a provider is configured.
  if (process.env.NODE_ENV !== 'production') {
    logger.info('email.dev_only', {
      to: payload.to,
      subject: payload.subject,
      text: payload.text,
    });
  }
}
