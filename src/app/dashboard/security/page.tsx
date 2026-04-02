'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';

type MfaStatusPayload = {
  ok: boolean;
  mfaEnabled: boolean;
  mfaPending: boolean;
  mfaEnabledAt: string | null;
  mfaPendingExpiresAt: string | null;
  mfaLastVerifiedAt: string | null;
  backupCodesRemaining: number;
};

type MessageState = {
  tone: 'neutral' | 'success' | 'warning' | 'error';
  text: string;
};

function messageClassName(tone: MessageState['tone']): string {
  if (tone === 'success') {
    return 'border-emerald-300/60 bg-emerald-100/70 text-emerald-900 dark:border-emerald-700/60 dark:bg-emerald-950/60 dark:text-emerald-200';
  }

  if (tone === 'warning') {
    return 'border-amber-300/60 bg-amber-100/70 text-amber-900 dark:border-amber-700/60 dark:bg-amber-950/60 dark:text-amber-200';
  }

  if (tone === 'error') {
    return 'border-rose-300/60 bg-rose-100/70 text-rose-900 dark:border-rose-700/60 dark:bg-rose-950/60 dark:text-rose-200';
  }

  return 'border-zinc-300/60 bg-zinc-100/70 text-zinc-900 dark:border-zinc-700/60 dark:bg-zinc-900/70 dark:text-zinc-200';
}

function formatDate(value: string | null): string {
  if (!value) {
    return 'Not available';
  }

  const parsed = new Date(value);

  if (Number.isNaN(parsed.getTime())) {
    return 'Not available';
  }

  return new Intl.DateTimeFormat('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(parsed);
}

async function parseJson(response: Response): Promise<Record<string, unknown>> {
  const payload = (await response.json().catch(() => ({}))) as unknown;

  if (!payload || typeof payload !== 'object') {
    return {};
  }

  return payload as Record<string, unknown>;
}

function readFormString(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === 'string' ? value : '';
}

function payloadErrorMessage(payload: Record<string, unknown>, fallback: string): string {
  const error = payload.error;
  return typeof error === 'string' ? error : fallback;
}

export default function DashboardSecurityPage() {
  const [status, setStatus] = useState<MfaStatusPayload | null>(null);
  const [message, setMessage] = useState<MessageState>({
    tone: 'neutral',
    text: 'Load your MFA status to begin enrollment or management.',
  });
  const [setupSecret, setSetupSecret] = useState('');
  const [otpAuthUrl, setOtpAuthUrl] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);

  async function refreshStatus(): Promise<void> {
    const response = await fetch('/api/auth/mfa/status', {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
      cache: 'no-store',
    });

    const payload = (await parseJson(response)) as Partial<MfaStatusPayload>;

    if (!response.ok) {
      setMessage({
        tone: 'error',
        text: 'Unable to load MFA status. You may need to sign in again.',
      });
      return;
    }

    setStatus({
      ok: Boolean(payload.ok),
      mfaEnabled: Boolean(payload.mfaEnabled),
      mfaPending: Boolean(payload.mfaPending),
      mfaEnabledAt: typeof payload.mfaEnabledAt === 'string' ? payload.mfaEnabledAt : null,
      mfaPendingExpiresAt:
        typeof payload.mfaPendingExpiresAt === 'string' ? payload.mfaPendingExpiresAt : null,
      mfaLastVerifiedAt:
        typeof payload.mfaLastVerifiedAt === 'string' ? payload.mfaLastVerifiedAt : null,
      backupCodesRemaining:
        typeof payload.backupCodesRemaining === 'number' ? payload.backupCodesRemaining : 0,
    });
  }

  useEffect(() => {
    void refreshStatus();
  }, []);

  async function onStartEnrollment(formData: FormData): Promise<void> {
    const password = readFormString(formData, 'password');

    const response = await fetch('/api/auth/mfa/enroll/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ password }),
    });

    const payload = await parseJson(response);

    if (!response.ok) {
      setMessage({
        tone: 'error',
        text: payloadErrorMessage(payload, 'Could not start MFA enrollment.'),
      });
      return;
    }

    setSetupSecret(typeof payload.secret === 'string' ? payload.secret : '');
    setOtpAuthUrl(typeof payload.otpAuthUrl === 'string' ? payload.otpAuthUrl : '');
    setMessage({
      tone: 'success',
      text: 'Enrollment initialized. Add this secret to your authenticator app and verify it below.',
    });

    await refreshStatus();
  }

  async function onVerifyEnrollment(formData: FormData): Promise<void> {
    const code = readFormString(formData, 'code');

    const response = await fetch('/api/auth/mfa/enroll/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ code }),
    });

    const payload = await parseJson(response);

    if (!response.ok) {
      setMessage({
        tone: 'error',
        text: payloadErrorMessage(payload, 'MFA verification failed.'),
      });
      return;
    }

    const issuedCodes = Array.isArray(payload.recoveryCodes)
      ? payload.recoveryCodes.filter(
          (codeEntry): codeEntry is string => typeof codeEntry === 'string'
        )
      : [];

    setRecoveryCodes(issuedCodes);
    setSetupSecret('');
    setOtpAuthUrl('');
    setMessage({
      tone: 'success',
      text: 'MFA enabled. Save your backup codes in a secure location.',
    });

    await refreshStatus();
  }

  async function onDisableMfa(formData: FormData): Promise<void> {
    const code = readFormString(formData, 'code');
    const backupCode = readFormString(formData, 'backupCode');

    const response = await fetch('/api/auth/mfa/disable', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ code, backupCode }),
    });

    const payload = await parseJson(response);

    if (!response.ok) {
      setMessage({
        tone: 'error',
        text: payloadErrorMessage(payload, 'Could not disable MFA.'),
      });
      return;
    }

    setRecoveryCodes([]);
    setSetupSecret('');
    setOtpAuthUrl('');
    setMessage({
      tone: 'warning',
      text: 'MFA has been disabled for your account.',
    });

    await refreshStatus();
  }

  return (
    <main className='mx-auto w-full max-w-5xl p-6'>
      <p className='text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500'>
        Account Security
      </p>
      <h1 className='mt-2 text-2xl font-semibold text-zinc-900 dark:text-zinc-100'>
        Multi-factor authentication
      </h1>
      <p className='mt-3 text-sm text-zinc-600 dark:text-zinc-300'>
        Enroll your authenticator app, store backup codes, and manage your MFA status.
      </p>

      <output
        className={`mt-4 rounded-lg border px-3 py-2 text-xs ${messageClassName(message.tone)}`}
        aria-live='polite'
      >
        {message.text}
      </output>

      <section className='mt-6 rounded-2xl border border-black/10 bg-white/80 p-4 dark:border-white/10 dark:bg-zinc-950/80'>
        <h2 className='text-sm font-semibold text-zinc-900 dark:text-zinc-100'>Current status</h2>
        <div className='mt-2 grid gap-1 text-xs text-zinc-600 dark:text-zinc-300'>
          <p>MFA enabled: {status?.mfaEnabled ? 'Yes' : 'No'}</p>
          <p>Enabled at: {formatDate(status?.mfaEnabledAt ?? null)}</p>
          <p>Pending enrollment: {status?.mfaPending ? 'Yes' : 'No'}</p>
          <p>Pending expires at: {formatDate(status?.mfaPendingExpiresAt ?? null)}</p>
          <p>Last MFA verification: {formatDate(status?.mfaLastVerifiedAt ?? null)}</p>
          <p>Backup codes remaining: {status?.backupCodesRemaining ?? 0}</p>
        </div>
      </section>

      {status?.mfaEnabled ? null : (
        <section className='mt-6 rounded-2xl border border-black/10 bg-white/80 p-4 dark:border-white/10 dark:bg-zinc-950/80'>
          <h2 className='text-sm font-semibold text-zinc-900 dark:text-zinc-100'>
            1) Start enrollment
          </h2>
          <form
            className='mt-3 flex flex-wrap items-center gap-2'
            action={async (formData) => {
              await onStartEnrollment(formData);
            }}
          >
            <input
              name='password'
              type='password'
              autoComplete='current-password'
              required
              placeholder='Confirm current password'
              className='min-w-60 rounded-lg border border-black/10 bg-white px-2 py-1 text-xs dark:border-white/20 dark:bg-zinc-950'
            />
            <button
              type='submit'
              className='rounded-lg border border-black/10 bg-white px-3 py-1 text-xs font-medium transition hover:bg-zinc-50 dark:border-white/20 dark:bg-zinc-900 dark:hover:bg-zinc-800'
            >
              Start MFA setup
            </button>
          </form>

          {setupSecret ? (
            <div className='mt-4 rounded-lg border border-zinc-300/60 bg-zinc-100/70 p-3 text-xs text-zinc-800 dark:border-zinc-700/60 dark:bg-zinc-900/70 dark:text-zinc-200'>
              <p className='font-semibold'>Authenticator secret</p>
              <p className='mt-1 break-all font-mono'>{setupSecret}</p>
              {otpAuthUrl ? (
                <p className='mt-2 break-all'>
                  OTP URI: <span className='font-mono'>{otpAuthUrl}</span>
                </p>
              ) : null}
            </div>
          ) : null}

          <h2 className='mt-5 text-sm font-semibold text-zinc-900 dark:text-zinc-100'>
            2) Verify enrollment
          </h2>
          <form
            className='mt-3 flex flex-wrap items-center gap-2'
            action={async (formData) => {
              await onVerifyEnrollment(formData);
            }}
          >
            <input
              name='code'
              type='text'
              inputMode='numeric'
              autoComplete='one-time-code'
              required
              placeholder='Authenticator code'
              className='min-w-48 rounded-lg border border-black/10 bg-white px-2 py-1 text-xs dark:border-white/20 dark:bg-zinc-950'
            />
            <button
              type='submit'
              className='rounded-lg border border-black/10 bg-white px-3 py-1 text-xs font-medium transition hover:bg-zinc-50 dark:border-white/20 dark:bg-zinc-900 dark:hover:bg-zinc-800'
            >
              Verify and enable MFA
            </button>
          </form>
        </section>
      )}

      {status?.mfaEnabled ? (
        <section className='mt-6 rounded-2xl border border-black/10 bg-white/80 p-4 dark:border-white/10 dark:bg-zinc-950/80'>
          <h2 className='text-sm font-semibold text-zinc-900 dark:text-zinc-100'>Disable MFA</h2>
          <p className='mt-2 text-xs text-zinc-600 dark:text-zinc-300'>
            Provide either your authenticator code or one backup code to disable MFA.
          </p>
          <form
            className='mt-3 grid gap-2 sm:grid-cols-3'
            action={async (formData) => {
              await onDisableMfa(formData);
            }}
          >
            <input
              name='code'
              type='text'
              inputMode='numeric'
              placeholder='Authenticator code'
              className='rounded-lg border border-black/10 bg-white px-2 py-1 text-xs dark:border-white/20 dark:bg-zinc-950'
            />
            <input
              name='backupCode'
              type='text'
              placeholder='Backup code'
              className='rounded-lg border border-black/10 bg-white px-2 py-1 text-xs dark:border-white/20 dark:bg-zinc-950'
            />
            <button
              type='submit'
              className='rounded-lg border border-black/10 bg-white px-3 py-1 text-xs font-medium transition hover:bg-zinc-50 dark:border-white/20 dark:bg-zinc-900 dark:hover:bg-zinc-800'
            >
              Disable MFA
            </button>
          </form>
        </section>
      ) : null}

      {recoveryCodes.length > 0 ? (
        <section className='mt-6 rounded-2xl border border-amber-300/60 bg-amber-100/70 p-4 dark:border-amber-700/60 dark:bg-amber-950/60'>
          <h2 className='text-sm font-semibold text-amber-900 dark:text-amber-200'>Backup codes</h2>
          <p className='mt-2 text-xs text-amber-800 dark:text-amber-300'>
            These codes are shown once. Store them in a password manager.
          </p>
          <ul className='mt-3 grid gap-1 font-mono text-xs text-amber-900 dark:text-amber-100'>
            {recoveryCodes.map((code) => (
              <li key={code}>{code}</li>
            ))}
          </ul>
        </section>
      ) : null}

      <div className='mt-6'>
        <Link
          href='/dashboard'
          className='inline-flex rounded-full border border-black/10 px-4 py-1.5 text-sm font-medium transition hover:bg-zinc-100 dark:border-white/20 dark:hover:bg-zinc-900'
        >
          Back to dashboard
        </Link>
      </div>
    </main>
  );
}
