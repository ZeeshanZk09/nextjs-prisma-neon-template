import { createHmac, timingSafeEqual } from 'node:crypto';

import prisma from '@/lib/prisma';

type LemonSqueezyPayload = {
  meta?: {
    event_name?: string;
  };
  data?: {
    id?: string | number;
    type?: string;
    attributes?: Record<string, unknown>;
  };
};

function toObject(value: unknown): Record<string, unknown> {
  if (typeof value === 'object' && value !== null) {
    return value as Record<string, unknown>;
  }

  return {};
}

function getString(value: unknown): string | null {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
  }

  if (typeof value === 'number') {
    return String(value);
  }

  return null;
}

function getBoolean(value: unknown): boolean | null {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true' || normalized === '1') {
      return true;
    }
    if (normalized === 'false' || normalized === '0') {
      return false;
    }
  }

  return null;
}

function getDate(value: unknown): Date | null {
  const dateString = getString(value);

  if (!dateString) {
    return null;
  }

  const date = new Date(dateString);
  return Number.isNaN(date.getTime()) ? null : date;
}

function getDecimalFromCents(value: unknown): number | null {
  const raw = getString(value);

  if (!raw) {
    return null;
  }

  const parsed = Number(raw);

  if (!Number.isFinite(parsed)) {
    return null;
  }

  return Number((parsed / 100).toFixed(2));
}

function mapSubscriptionStatus(
  eventName: string,
  rawStatus: string | null
): 'TRIALING' | 'ACTIVE' | 'PAST_DUE' | 'CANCELED' | 'EXPIRED' | 'PAUSED' {
  const status = (rawStatus ?? '').toLowerCase();

  if (status === 'trialing') {
    return 'TRIALING';
  }

  if (status === 'past_due' || eventName.includes('payment_failed')) {
    return 'PAST_DUE';
  }

  if (status === 'cancelled' || status === 'canceled' || eventName.includes('cancelled')) {
    return 'CANCELED';
  }

  if (status === 'expired' || eventName.includes('expired')) {
    return 'EXPIRED';
  }

  if (status === 'paused' || eventName.includes('paused')) {
    return 'PAUSED';
  }

  return 'ACTIVE';
}

function mapInvoiceStatus(
  eventName: string
): 'DRAFT' | 'OPEN' | 'PAID' | 'VOID' | 'UNCOLLECTIBLE' | 'FAILED' | 'REFUNDED' {
  const normalizedEvent = eventName.toLowerCase();

  if (normalizedEvent.includes('refunded')) {
    return 'REFUNDED';
  }

  if (normalizedEvent.includes('payment_failed') || normalizedEvent.includes('failed')) {
    return 'FAILED';
  }

  if (normalizedEvent.includes('payment_success') || normalizedEvent.includes('paid')) {
    return 'PAID';
  }

  return 'OPEN';
}

export function getLemonSqueezyEventName(payload: unknown): string {
  const objectPayload = toObject(payload);
  const meta = toObject(objectPayload.meta);
  return getString(meta.event_name) ?? 'unknown';
}

export function getLemonSqueezyExternalEventId(payload: unknown, payloadHash: string): string {
  const eventName = getLemonSqueezyEventName(payload);
  const objectPayload = toObject(payload);
  const data = toObject(objectPayload.data);
  const attributes = toObject(data.attributes);

  const entityId = getString(data.id) ?? 'unknown';
  const timestamp = getString(attributes.updated_at) ?? getString(attributes.created_at);

  if (timestamp) {
    return `${eventName}:${entityId}:${timestamp}`;
  }

  return `${eventName}:${entityId}:${payloadHash.slice(0, 16)}`;
}

export function verifyLemonSqueezySignature(
  rawBody: string,
  signature: string | null,
  secret: string
): boolean {
  if (!signature || !secret) {
    return false;
  }

  const expected = createHmac('sha256', secret).update(rawBody).digest('hex');
  const signatureBuffer = Buffer.from(signature, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');

  if (signatureBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(signatureBuffer, expectedBuffer);
}

async function processSubscriptionEvent(payload: LemonSqueezyPayload): Promise<void> {
  const eventName = getLemonSqueezyEventName(payload);
  const data = toObject(payload.data);
  const attributes = toObject(data.attributes);

  const userEmail =
    getString(attributes.user_email)?.toLowerCase() ??
    getString(attributes.customer_email)?.toLowerCase() ??
    null;

  if (!userEmail) {
    return;
  }

  const user = await prisma.user.findUnique({
    where: {
      email: userEmail,
    },
    select: {
      id: true,
    },
  });

  if (!user) {
    return;
  }

  const providerSubscriptionId = getString(data.id) ?? getString(attributes.subscription_id);

  if (!providerSubscriptionId) {
    return;
  }

  const variantId = getString(attributes.variant_id);
  const plan = variantId
    ? await prisma.plan.findFirst({
        where: {
          providerVariantId: variantId,
        },
        select: {
          id: true,
        },
      })
    : await prisma.plan.findFirst({
        where: {
          isActive: true,
        },
        select: {
          id: true,
        },
        orderBy: {
          createdAt: 'asc',
        },
      });

  if (!plan) {
    return;
  }

  const status = mapSubscriptionStatus(eventName, getString(attributes.status));
  const cancelAtPeriodEnd = getBoolean(attributes.cancelled) ?? false;

  await prisma.subscription.upsert({
    where: {
      providerSubscriptionId,
    },
    create: {
      userId: user.id,
      planId: plan.id,
      providerSubscriptionId,
      status,
      startDate: getDate(attributes.created_at) ?? new Date(),
      endDate: getDate(attributes.ends_at),
      currentPeriodEnd: getDate(attributes.renews_at),
      cancelAtPeriodEnd,
      gracePeriodEndsAt: getDate(attributes.grace_period_ends_at),
      canceledAt: getDate(attributes.cancelled_at),
    },
    update: {
      userId: user.id,
      planId: plan.id,
      status,
      endDate: getDate(attributes.ends_at),
      currentPeriodEnd: getDate(attributes.renews_at),
      cancelAtPeriodEnd,
      gracePeriodEndsAt: getDate(attributes.grace_period_ends_at),
      canceledAt: getDate(attributes.cancelled_at),
    },
  });
}

async function processInvoiceEvent(payload: LemonSqueezyPayload): Promise<void> {
  const eventName = getLemonSqueezyEventName(payload);
  const data = toObject(payload.data);
  const attributes = toObject(data.attributes);

  const providerInvoiceId = getString(data.id);

  if (!providerInvoiceId) {
    return;
  }

  const userEmail =
    getString(attributes.user_email)?.toLowerCase() ??
    getString(attributes.customer_email)?.toLowerCase() ??
    null;

  if (!userEmail) {
    return;
  }

  const user = await prisma.user.findUnique({
    where: {
      email: userEmail,
    },
    select: {
      id: true,
    },
  });

  if (!user) {
    return;
  }

  const providerSubscriptionId = getString(attributes.subscription_id);
  const subscription = providerSubscriptionId
    ? await prisma.subscription.findUnique({
        where: {
          providerSubscriptionId,
        },
        select: {
          id: true,
        },
      })
    : null;

  const amount =
    getDecimalFromCents(attributes.total) ??
    getDecimalFromCents(attributes.subtotal) ??
    getDecimalFromCents(attributes.total_usd) ??
    0;

  const currency = getString(attributes.currency)?.toUpperCase() ?? 'USD';
  const status = mapInvoiceStatus(eventName);
  const paidAt = status === 'PAID' ? (getDate(attributes.updated_at) ?? new Date()) : null;

  await prisma.invoice.upsert({
    where: {
      providerInvoiceId,
    },
    create: {
      userId: user.id,
      subscriptionId: subscription?.id ?? null,
      providerInvoiceId,
      amount,
      currency,
      status,
      date: getDate(attributes.created_at) ?? new Date(),
      paidAt,
      failureReason: status === 'FAILED' ? 'Payment failed' : null,
    },
    update: {
      userId: user.id,
      subscriptionId: subscription?.id ?? null,
      amount,
      currency,
      status,
      paidAt,
      failureReason: status === 'FAILED' ? 'Payment failed' : null,
    },
  });
}

export async function processLemonSqueezyEvent(payload: unknown): Promise<void> {
  const eventName = getLemonSqueezyEventName(payload).toLowerCase();
  const parsedPayload = toObject(payload) as LemonSqueezyPayload;

  if (eventName.startsWith('subscription_')) {
    await processSubscriptionEvent(parsedPayload);
    return;
  }

  if (
    eventName.startsWith('order_') ||
    eventName.includes('payment_') ||
    eventName.includes('invoice_')
  ) {
    await processInvoiceEvent(parsedPayload);
  }
}
