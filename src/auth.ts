import { PrismaAdapter } from '@auth/prisma-adapter';
import NextAuth from 'next-auth';
import type { Provider } from 'next-auth/providers';
import Credentials from 'next-auth/providers/credentials';
import GitHub from 'next-auth/providers/github';
import Google from 'next-auth/providers/google';

import { env } from '@/lib/env';
import prisma from '@/lib/prisma';
import { verifyMfaChallenge } from '@/lib/security/mfa';
import { verifyPassword } from '@/lib/security/password';
import { credentialsSignInSchema } from '@/lib/validations/auth';

const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCK_WINDOW_MS = 15 * 60 * 1000;

const providers: Provider[] = [
  Credentials({
    name: 'Credentials',
    credentials: {
      email: { label: 'Email', type: 'email' },
      password: { label: 'Password', type: 'password' },
      mfaCode: { label: 'MFA Code', type: 'text' },
      backupCode: { label: 'Backup Code', type: 'text' },
    },
    async authorize(credentials) {
      const parsedCredentials = credentialsSignInSchema.safeParse(credentials);

      if (!parsedCredentials.success) {
        return null;
      }

      const email = parsedCredentials.data.email.toLowerCase();

      const user = await prisma.user.findUnique({
        where: { email },
        select: {
          id: true,
          name: true,
          email: true,
          image: true,
          emailVerified: true,
          passwordHash: true,
          status: true,
          isBlocked: true,
          mfaEnabled: true,
          mfaSecretEncrypted: true,
          mfaRecoveryCodeHashes: true,
          failedLoginAttempts: true,
          lockedUntil: true,
        },
      });

      if (!user?.passwordHash) {
        return null;
      }

      if (user.status !== 'ACTIVE' || user.isBlocked) {
        return null;
      }

      if (user.lockedUntil && user.lockedUntil > new Date()) {
        return null;
      }

      if (!user.emailVerified) {
        return null;
      }

      const isPasswordValid = await verifyPassword(
        parsedCredentials.data.password,
        user.passwordHash
      );

      if (!isPasswordValid) {
        const failedAttempts = user.failedLoginAttempts + 1;
        const shouldLock = failedAttempts >= LOGIN_MAX_ATTEMPTS;

        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: failedAttempts,
            lockedUntil: shouldLock
              ? new Date(Date.now() + LOGIN_LOCK_WINDOW_MS)
              : user.lockedUntil,
          },
        });

        return null;
      }

      const mfaCheck = verifyMfaChallenge({
        mfaEnabled: user.mfaEnabled,
        mfaSecretEncrypted: user.mfaSecretEncrypted,
        mfaRecoveryCodeHashes: user.mfaRecoveryCodeHashes,
        code: parsedCredentials.data.mfaCode,
        backupCode: parsedCredentials.data.backupCode,
      });

      if (!mfaCheck.verified) {
        const failedAttempts = user.failedLoginAttempts + 1;
        const shouldLock = failedAttempts >= LOGIN_MAX_ATTEMPTS;

        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: failedAttempts,
            lockedUntil: shouldLock
              ? new Date(Date.now() + LOGIN_LOCK_WINDOW_MS)
              : user.lockedUntil,
          },
        });

        return null;
      }

      const mfaUpdateData: { mfaRecoveryCodeHashes?: string[] } = {};

      if (mfaCheck.remainingRecoveryCodeHashes === undefined) {
        // No-op; keep existing backup hashes unless one was consumed.
      } else {
        mfaUpdateData.mfaRecoveryCodeHashes = mfaCheck.remainingRecoveryCodeHashes;
      }

      await prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: 0,
          lockedUntil: null,
          lastLoginAt: new Date(),
          mfaLastVerifiedAt: user.mfaEnabled ? new Date() : null,
          ...mfaUpdateData,
        },
      });

      return {
        id: user.id,
        name: user.name,
        email: user.email,
        image: user.image,
      };
    },
  }),
];

if (env.AUTH_GOOGLE_ID && env.AUTH_GOOGLE_SECRET) {
  providers.push(
    Google({
      clientId: env.AUTH_GOOGLE_ID,
      clientSecret: env.AUTH_GOOGLE_SECRET,
      authorization: {
        params: {
          prompt: 'consent',
        },
      },
    })
  );
}

if (env.AUTH_GITHUB_ID && env.AUTH_GITHUB_SECRET) {
  providers.push(
    GitHub({
      clientId: env.AUTH_GITHUB_ID,
      clientSecret: env.AUTH_GITHUB_SECRET,
    })
  );
}

export const { auth, handlers, signIn, signOut } = NextAuth({
  secret: env.AUTH_SECRET,
  adapter: PrismaAdapter(prisma as any),
  session: {
    strategy: 'database',
    maxAge: 60 * 60 * 24 * 30,
    updateAge: 60 * 60 * 8,
  },
  trustHost: true,
  pages: {
    signIn: '/login',
  },
  providers,
  callbacks: {
    async signIn({ user }) {
      if (!user.id) {
        return false;
      }

      const dbUser = await prisma.user.findUnique({
        where: { id: user.id },
        select: { status: true, isBlocked: true },
      });

      return dbUser?.status === 'ACTIVE' && !dbUser?.isBlocked;
    },
    async session({ session, user }) {
      if (!session.user || !user?.id) {
        return session;
      }

      const [dbUser, roleRows] = await Promise.all([
        prisma.user.findUnique({
          where: { id: user.id },
          select: {
            authVersion: true,
            isBlocked: true,
            status: true,
            emailVerified: true,
            mfaEnabled: true,
            mfaLastVerifiedAt: true,
          },
        }),
        prisma.userRole.findMany({
          where: {
            userId: user.id,
            OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
          },
          select: {
            role: {
              select: {
                name: true,
              },
            },
          },
        }),
      ]);

      if (!dbUser) {
        return session;
      }

      session.user.id = user.id;
      session.user.authVersion = dbUser.authVersion;
      session.user.roles = roleRows.map((row) => row.role.name);
      session.user.isBlocked = dbUser.isBlocked;
      session.user.status = dbUser.status;
      session.user.emailVerified = dbUser.emailVerified ?? null;
      session.user.mfaEnabled = dbUser.mfaEnabled;
      session.user.mfaLastVerifiedAt = dbUser.mfaLastVerifiedAt ?? null;

      return session;
    },
  },
});
