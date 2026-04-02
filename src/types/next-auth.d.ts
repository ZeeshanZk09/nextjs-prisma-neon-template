import type { DefaultSession } from 'next-auth';

declare module 'next-auth' {
  interface Session {
    user: DefaultSession['user'] & {
      id: string;
      authVersion: number;
      roles: string[];
      isBlocked: boolean;
      status: string;
      emailVerified: Date | null;
      mfaEnabled: boolean;
      mfaLastVerifiedAt: Date | null;
    };
  }
}
