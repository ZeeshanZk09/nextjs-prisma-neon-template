import Link from 'next/link';

import { auth } from '@/auth';
import { ThemeToggle } from '@/components/theme-toggle';

export default async function Home() {
  const session = await auth();

  return (
    <main className='mx-auto grid min-h-screen w-full max-w-5xl content-center gap-8 p-6'>
      <header className='flex flex-wrap items-center justify-between gap-3'>
        <div>
          <p className='text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500'>
            Auth Management
          </p>
          <h1 className='text-3xl font-semibold text-zinc-900 dark:text-zinc-100'>
            Security-first Auth, Billing, and RBAC
          </h1>
        </div>
        <ThemeToggle />
      </header>

      <section className='rounded-2xl border border-black/10 bg-white/70 p-6 dark:border-white/10 dark:bg-zinc-950/70'>
        <p className='text-sm text-zinc-600 dark:text-zinc-300'>
          Iteration 1 includes hardened Prisma schema, Auth.js setup, protected routes, role-aware
          checks, and backend session revocation endpoints.
        </p>

        <div className='mt-6 flex flex-wrap gap-2'>
          {session?.user ? (
            <>
              <Link
                href='/dashboard'
                className='rounded-full bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300'
              >
                Open dashboard
              </Link>
              <Link
                href='/admin'
                className='rounded-full border border-black/10 px-4 py-2 text-sm font-medium transition hover:bg-zinc-100 dark:border-white/20 dark:hover:bg-zinc-900'
              >
                Open admin area
              </Link>
            </>
          ) : (
            <Link
              href='/login'
              className='rounded-full bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300'
            >
              Start with login
            </Link>
          )}
        </div>
      </section>
    </main>
  );
}
