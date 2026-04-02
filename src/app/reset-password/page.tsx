import Link from 'next/link';
import { redirect } from 'next/navigation';

import { resetPasswordFlow } from '@/lib/auth/workflows';
import { getFormString } from '@/lib/forms';
import { completePasswordResetSchema } from '@/lib/validations/auth';

function firstParam(value: string | string[] | undefined): string {
  if (Array.isArray(value)) {
    return value[0] ?? '';
  }

  if (typeof value === 'string') {
    return value;
  }

  return '';
}

async function resetPasswordAction(formData: FormData): Promise<void> {
  'use server';

  const email = getFormString(formData, 'email');
  const token = getFormString(formData, 'token');

  const parsed = completePasswordResetSchema.safeParse({
    email,
    token,
    password: getFormString(formData, 'password'),
  });

  if (!parsed.success) {
    redirect(
      `/reset-password?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}&error=invalid`
    );
  }

  const reset = await resetPasswordFlow({
    email: parsed.data.email,
    token: parsed.data.token,
    password: parsed.data.password,
  });

  if (!reset) {
    redirect(
      `/reset-password?email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}&error=token`
    );
  }

  redirect('/login?passwordReset=1');
}

export default async function ResetPasswordPage({
  searchParams,
}: Readonly<{
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}>) {
  const params = await searchParams;
  const defaultEmail = firstParam(params.email);
  const defaultToken = firstParam(params.token);
  const hasInvalidToken = firstParam(params.error) === 'token';

  return (
    <main className='mx-auto flex min-h-screen w-full max-w-5xl items-center justify-center p-6'>
      <section className='w-full max-w-md rounded-2xl border border-black/10 bg-white/80 p-6 shadow-sm backdrop-blur dark:border-white/10 dark:bg-zinc-950/80'>
        <p className='text-xs font-semibold uppercase tracking-[0.18em] text-zinc-500'>
          Password Reset
        </p>
        <h1 className='mt-2 text-2xl font-semibold text-zinc-900 dark:text-zinc-100'>
          Set a new password
        </h1>
        <p className='mt-2 text-sm text-zinc-600 dark:text-zinc-400'>
          Submit the reset token from your email and choose a new password.
        </p>

        {hasInvalidToken ? (
          <p className='mt-4 rounded-xl border border-amber-300/60 bg-amber-100/70 px-3 py-2 text-xs text-amber-900 dark:border-amber-700/60 dark:bg-amber-950/60 dark:text-amber-200'>
            Reset token is invalid or expired.
          </p>
        ) : null}

        <form action={resetPasswordAction} className='mt-6 grid gap-3'>
          <input
            name='email'
            type='email'
            autoComplete='email'
            required
            defaultValue={defaultEmail}
            placeholder='you@example.com'
            className='w-full rounded-xl border border-black/10 bg-white px-3 py-2 text-sm outline-none placeholder:text-zinc-400 focus:border-zinc-400 dark:border-white/20 dark:bg-zinc-900'
          />
          <input
            name='token'
            type='text'
            required
            defaultValue={defaultToken}
            placeholder='Paste reset token'
            className='w-full rounded-xl border border-black/10 bg-white px-3 py-2 text-sm outline-none placeholder:text-zinc-400 focus:border-zinc-400 dark:border-white/20 dark:bg-zinc-900'
          />
          <input
            name='password'
            type='password'
            autoComplete='new-password'
            required
            placeholder='At least 12 characters'
            className='w-full rounded-xl border border-black/10 bg-white px-3 py-2 text-sm outline-none placeholder:text-zinc-400 focus:border-zinc-400 dark:border-white/20 dark:bg-zinc-900'
          />
          <button
            type='submit'
            className='mt-2 rounded-xl bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300'
          >
            Update password
          </button>
        </form>

        <Link
          href='/login'
          className='mt-4 inline-block text-sm font-medium text-zinc-700 underline-offset-2 hover:underline dark:text-zinc-300'
        >
          Back to sign in
        </Link>
      </section>
    </main>
  );
}
