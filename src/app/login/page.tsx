import Link from 'next/link';

import { signIn } from '@/auth';
import { getFormString } from '@/lib/forms';

function getSearchParam(
  params: Record<string, string | string[] | undefined>,
  key: string
): string {
  const value = params[key];

  if (Array.isArray(value)) {
    return value[0] ?? '';
  }

  if (typeof value === 'string') {
    return value;
  }

  return '';
}

async function signInWithCredentials(formData: FormData): Promise<void> {
  'use server';

  const email = getFormString(formData, 'email').trim();
  const password = getFormString(formData, 'password');
  const mfaCode = getFormString(formData, 'mfaCode').trim();
  const backupCode = getFormString(formData, 'backupCode').trim();

  await signIn('credentials', {
    email,
    password,
    mfaCode,
    backupCode,
    redirectTo: '/dashboard',
  });
}

async function signInWithProvider(formData: FormData): Promise<void> {
  'use server';

  const provider = getFormString(formData, 'provider');

  if (provider !== 'google' && provider !== 'github') {
    return;
  }

  await signIn(provider, {
    redirectTo: '/dashboard',
  });
}

export default async function LoginPage({
  searchParams,
}: Readonly<{
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}>) {
  const params = await searchParams;
  const registered = getSearchParam(params, 'registered') === '1';
  const verified = getSearchParam(params, 'verified') === '1';
  const verifyError = getSearchParam(params, 'verifyError') === '1';
  const resetRequested = getSearchParam(params, 'resetRequested') === '1';
  const passwordReset = getSearchParam(params, 'passwordReset') === '1';

  return (
    <main className='mx-auto flex min-h-screen w-full max-w-5xl items-center justify-center p-6'>
      <section className='w-full max-w-md rounded-2xl border border-black/10 bg-white/80 p-6 shadow-sm backdrop-blur dark:border-white/10 dark:bg-zinc-950/80'>
        <p className='text-xs font-semibold uppercase tracking-[0.18em] text-zinc-500'>
          Secure Access
        </p>
        <h1 className='mt-2 text-2xl font-semibold text-zinc-900 dark:text-zinc-100'>
          Sign in to continue
        </h1>
        <p className='mt-2 text-sm text-zinc-600 dark:text-zinc-400'>
          Credentials are verified server-side with account lockout, MFA challenge support, and
          role-aware session checks.
        </p>

        {registered ? (
          <p className='mt-4 rounded-xl border border-emerald-300/60 bg-emerald-100/70 px-3 py-2 text-xs text-emerald-900 dark:border-emerald-700/60 dark:bg-emerald-950/60 dark:text-emerald-200'>
            Registration accepted. Check your inbox for the verification link.
          </p>
        ) : null}

        {verified ? (
          <p className='mt-4 rounded-xl border border-emerald-300/60 bg-emerald-100/70 px-3 py-2 text-xs text-emerald-900 dark:border-emerald-700/60 dark:bg-emerald-950/60 dark:text-emerald-200'>
            Email verified. You can now sign in.
          </p>
        ) : null}

        {verifyError ? (
          <p className='mt-4 rounded-xl border border-amber-300/60 bg-amber-100/70 px-3 py-2 text-xs text-amber-900 dark:border-amber-700/60 dark:bg-amber-950/60 dark:text-amber-200'>
            Verification link is invalid or expired.
          </p>
        ) : null}

        {resetRequested ? (
          <p className='mt-4 rounded-xl border border-sky-300/60 bg-sky-100/70 px-3 py-2 text-xs text-sky-900 dark:border-sky-700/60 dark:bg-sky-950/60 dark:text-sky-200'>
            If your account exists, a password reset email has been sent.
          </p>
        ) : null}

        {passwordReset ? (
          <p className='mt-4 rounded-xl border border-emerald-300/60 bg-emerald-100/70 px-3 py-2 text-xs text-emerald-900 dark:border-emerald-700/60 dark:bg-emerald-950/60 dark:text-emerald-200'>
            Password updated successfully. Sign in with your new password.
          </p>
        ) : null}

        <form action={signInWithCredentials} className='mt-6 grid gap-3'>
          <input
            name='email'
            type='email'
            autoComplete='email'
            required
            placeholder='you@example.com'
            className='w-full rounded-xl border border-black/10 bg-white px-3 py-2 text-sm outline-none ring-0 placeholder:text-zinc-400 focus:border-zinc-400 dark:border-white/20 dark:bg-zinc-900'
          />
          <input
            name='password'
            type='password'
            autoComplete='current-password'
            required
            placeholder='Your password'
            className='w-full rounded-xl border border-black/10 bg-white px-3 py-2 text-sm outline-none ring-0 placeholder:text-zinc-400 focus:border-zinc-400 dark:border-white/20 dark:bg-zinc-900'
          />
          <input
            name='mfaCode'
            type='text'
            inputMode='numeric'
            autoComplete='one-time-code'
            placeholder='MFA code (if enabled)'
            className='w-full rounded-xl border border-black/10 bg-white px-3 py-2 text-sm outline-none ring-0 placeholder:text-zinc-400 focus:border-zinc-400 dark:border-white/20 dark:bg-zinc-900'
          />
          <input
            name='backupCode'
            type='text'
            autoComplete='off'
            placeholder='Backup code (optional)'
            className='w-full rounded-xl border border-black/10 bg-white px-3 py-2 text-sm outline-none ring-0 placeholder:text-zinc-400 focus:border-zinc-400 dark:border-white/20 dark:bg-zinc-900'
          />
          <button
            type='submit'
            className='mt-2 rounded-xl bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300'
          >
            Sign in with email
          </button>
        </form>

        <div className='mt-4 grid grid-cols-1 gap-2 sm:grid-cols-2'>
          <form action={signInWithProvider}>
            <input type='hidden' name='provider' value='google' />
            <button
              type='submit'
              className='w-full rounded-xl border border-black/10 px-4 py-2 text-sm font-medium transition hover:bg-zinc-100 dark:border-white/20 dark:hover:bg-zinc-900'
            >
              Continue with Google
            </button>
          </form>

          <form action={signInWithProvider}>
            <input type='hidden' name='provider' value='github' />
            <button
              type='submit'
              className='w-full rounded-xl border border-black/10 px-4 py-2 text-sm font-medium transition hover:bg-zinc-100 dark:border-white/20 dark:hover:bg-zinc-900'
            >
              Continue with GitHub
            </button>
          </form>
        </div>

        <p className='mt-6 text-xs text-zinc-500 dark:text-zinc-400'>
          Need to bootstrap users and roles? Seed initial admin records after running migrations.
        </p>

        <Link
          href='/'
          className='mt-4 inline-block text-sm font-medium text-zinc-700 underline-offset-2 hover:underline dark:text-zinc-300'
        >
          Back to home
        </Link>

        <div className='mt-2 flex flex-wrap gap-3 text-sm text-zinc-600 dark:text-zinc-300'>
          <Link href='/register' className='underline-offset-2 hover:underline'>
            Create account
          </Link>
          <Link href='/forgot-password' className='underline-offset-2 hover:underline'>
            Forgot password
          </Link>
        </div>
      </section>
    </main>
  );
}
