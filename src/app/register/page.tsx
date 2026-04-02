import Link from 'next/link';
import { redirect } from 'next/navigation';

import { registerUserFlow } from '@/lib/auth/workflows';
import { getFormString } from '@/lib/forms';
import { registerUserSchema } from '@/lib/validations/auth';

async function registerAction(formData: FormData): Promise<void> {
  'use server';

  const parsed = registerUserSchema.safeParse({
    name: getFormString(formData, 'name'),
    email: getFormString(formData, 'email'),
    password: getFormString(formData, 'password'),
  });

  if (!parsed.success) {
    redirect('/register?error=invalid');
  }

  await registerUserFlow(parsed.data);
  redirect('/login?registered=1');
}

export default function RegisterPage() {
  return (
    <main className='mx-auto flex min-h-screen w-full max-w-5xl items-center justify-center p-6'>
      <section className='w-full max-w-md rounded-2xl border border-black/10 bg-white/80 p-6 shadow-sm backdrop-blur dark:border-white/10 dark:bg-zinc-950/80'>
        <p className='text-xs font-semibold uppercase tracking-[0.18em] text-zinc-500'>
          Registration
        </p>
        <h1 className='mt-2 text-2xl font-semibold text-zinc-900 dark:text-zinc-100'>
          Create your account
        </h1>
        <p className='mt-2 text-sm text-zinc-600 dark:text-zinc-400'>
          New accounts require email verification before credential sign-in.
        </p>

        <form action={registerAction} className='mt-6 grid gap-3'>
          <input
            name='name'
            type='text'
            autoComplete='name'
            required
            placeholder='Your name'
            className='w-full rounded-xl border border-black/10 bg-white px-3 py-2 text-sm outline-none placeholder:text-zinc-400 focus:border-zinc-400 dark:border-white/20 dark:bg-zinc-900'
          />
          <input
            name='email'
            type='email'
            autoComplete='email'
            required
            placeholder='you@example.com'
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
            Register
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
