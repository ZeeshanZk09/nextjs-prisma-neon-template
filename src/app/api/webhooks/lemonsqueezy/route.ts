import { createHash } from 'node:crypto';

import {
  getLemonSqueezyEventName,
  getLemonSqueezyExternalEventId,
  processLemonSqueezyEvent,
  verifyLemonSqueezySignature,
} from '@/lib/billing/lemonsqueezy-webhook';
import { env } from '@/lib/env';
import { logger } from '@/lib/logger';
import prisma from '@/lib/prisma';

const WEBHOOK_PROVIDER = 'LEMON_SQUEEZY';

function asErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  if (typeof error === 'string') {
    return error;
  }

  if (typeof error === 'number' || typeof error === 'boolean') {
    return `${error}`;
  }

  try {
    return JSON.stringify(error);
  } catch {
    return 'Unknown error';
  }
}

export async function POST(request: Request): Promise<Response> {
  const webhookSecret = env.LEMONSQUEEZY_WEBHOOK_SECRET;

  if (!webhookSecret) {
    logger.error('billing.webhook.secret_missing', { path: '/api/webhooks/lemonsqueezy' });
    return Response.json({ error: 'Webhook secret is not configured' }, { status: 500 });
  }

  const signature = request.headers.get('x-signature');
  const rawBody = await request.text();

  if (!verifyLemonSqueezySignature(rawBody, signature, webhookSecret)) {
    logger.warn('billing.webhook.signature_invalid', { path: '/api/webhooks/lemonsqueezy' });
    return Response.json({ error: 'Invalid webhook signature' }, { status: 401 });
  }

  let payload: unknown;

  try {
    payload = JSON.parse(rawBody) as unknown;
  } catch {
    return Response.json({ error: 'Invalid JSON payload' }, { status: 400 });
  }

  const payloadHash = createHash('sha256').update(rawBody).digest('hex');
  const externalEventId = getLemonSqueezyExternalEventId(payload, payloadHash);
  const eventName = getLemonSqueezyEventName(payload);

  const existingEvent = await prisma.billingWebhookEvent.findUnique({
    where: {
      provider_externalEventId: {
        provider: WEBHOOK_PROVIDER,
        externalEventId,
      },
    },
    select: {
      id: true,
      status: true,
    },
  });

  if (existingEvent) {
    logger.info('billing.webhook.duplicate_event', {
      path: '/api/webhooks/lemonsqueezy',
      eventId: externalEventId,
      status: existingEvent.status,
    });
    return Response.json({ ok: true, duplicate: true, status: existingEvent.status });
  }

  let webhookEventId = '';

  try {
    const createdEvent = await prisma.billingWebhookEvent.create({
      data: {
        provider: WEBHOOK_PROVIDER,
        externalEventId,
        signatureVerified: true,
        payloadHash,
        payload: payload as any,
        status: 'RECEIVED',
      },
      select: {
        id: true,
      },
    });

    webhookEventId = createdEvent.id;
  } catch (error) {
    const message = asErrorMessage(error).toLowerCase();

    if (message.includes('unique constraint')) {
      logger.info('billing.webhook.duplicate_write_race', {
        path: '/api/webhooks/lemonsqueezy',
        eventId: externalEventId,
      });
      return Response.json({ ok: true, duplicate: true });
    }

    logger.error('billing.webhook.persist_failed', {
      path: '/api/webhooks/lemonsqueezy',
      error: asErrorMessage(error),
    });

    return Response.json({ error: 'Could not persist webhook event' }, { status: 500 });
  }

  try {
    await processLemonSqueezyEvent(payload);

    await prisma.billingWebhookEvent.update({
      where: {
        id: webhookEventId,
      },
      data: {
        status: 'PROCESSED',
        processedAt: new Date(),
      },
    });

    logger.info('billing.webhook.processed', {
      path: '/api/webhooks/lemonsqueezy',
      event: eventName,
      eventId: externalEventId,
    });

    return Response.json({ ok: true, event: eventName });
  } catch (error) {
    await prisma.billingWebhookEvent.update({
      where: {
        id: webhookEventId,
      },
      data: {
        status: 'FAILED',
        error: asErrorMessage(error).slice(0, 500),
        processedAt: new Date(),
      },
    });

    logger.error('billing.webhook.processing_failed', {
      path: '/api/webhooks/lemonsqueezy',
      event: eventName,
      eventId: externalEventId,
      error: asErrorMessage(error),
    });

    return Response.json({ error: 'Webhook processing failed' }, { status: 500 });
  }
}
