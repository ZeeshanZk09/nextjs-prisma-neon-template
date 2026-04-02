import Link from 'next/link';
import { redirect } from 'next/navigation';

import { auth, signOut } from '@/auth';
import { ThemeToggle } from '@/components/theme-toggle';

async function signOutAction(): Promise<void> {
  'use server';

  await signOut({ redirectTo: '/login' });
}

export default async function DashboardPage() {
  const session = await auth();

  if (!session?.user) {
    redirect('/login');
  }

  return (
    <main className='mx-auto w-full max-w-5xl p-6'>
      <header className='flex flex-wrap items-center justify-between gap-3'>
        <div>
          <p className='text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500'>
            Dashboard
          </p>
          <h1 className='text-2xl font-semibold text-zinc-900 dark:text-zinc-100'>
            Welcome, {session.user.name ?? session.user.email}
          </h1>
        </div>
        <div className='flex items-center gap-2'>
          <ThemeToggle />
          <form action={signOutAction}>
            <button
              type='submit'
              className='rounded-full border border-black/10 px-4 py-1.5 text-sm font-medium transition hover:bg-zinc-100 dark:border-white/20 dark:hover:bg-zinc-900'
            >
              Sign out
            </button>
          </form>
        </div>
      </header>

      <section className='mt-8 grid gap-4 rounded-2xl border border-black/10 bg-white/70 p-4 dark:border-white/10 dark:bg-zinc-950/70'>
        <p className='text-sm text-zinc-600 dark:text-zinc-300'>
          This is the first secured area. Next iterations will wire billing widgets, notifications,
          and account controls.
        </p>
        <p className='text-sm text-zinc-600 dark:text-zinc-300'>
          Active roles: {session.user.roles.length > 0 ? session.user.roles.join(', ') : 'None'}
        </p>
        <Link
          href='/admin'
          className='inline-flex w-fit rounded-full border border-black/10 px-4 py-1.5 text-sm font-medium transition hover:bg-zinc-100 dark:border-white/20 dark:hover:bg-zinc-900'
        >
          Go to admin area
        </Link>
        <Link
          href='/dashboard/security'
          className='inline-flex w-fit rounded-full border border-black/10 px-4 py-1.5 text-sm font-medium transition hover:bg-zinc-100 dark:border-white/20 dark:hover:bg-zinc-900'
        >
          Manage MFA security
        </Link>
      </section>
    </main>
  );
}
