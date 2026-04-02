'use client';

import { Monitor, Moon, Sun } from 'lucide-react';
import { useTheme } from 'next-themes';
import { useEffect, useMemo, useState } from 'react';

const THEME_ORDER = ['light', 'dark', 'system'] as const;

function themeIcon(theme: string) {
  if (theme === 'light') {
    return <Sun size={16} aria-hidden='true' />;
  }

  if (theme === 'dark') {
    return <Moon size={16} aria-hidden='true' />;
  }

  return <Monitor size={16} aria-hidden='true' />;
}

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const activeTheme = useMemo(() => {
    if (!mounted || !theme) {
      return 'system';
    }

    return theme;
  }, [mounted, theme]);

  const currentIndex = THEME_ORDER.indexOf(activeTheme as (typeof THEME_ORDER)[number]);
  const nextTheme = THEME_ORDER[(currentIndex + 1) % THEME_ORDER.length];

  return (
    <button
      type='button'
      onClick={() => setTheme(nextTheme)}
      className='inline-flex items-center gap-2 rounded-full border border-black/10 bg-white/70 px-3 py-1.5 text-sm font-medium text-black backdrop-blur transition hover:bg-white dark:border-white/20 dark:bg-zinc-900/80 dark:text-white'
      aria-label={`Switch theme from ${activeTheme} to ${nextTheme}`}
      title={`Theme: ${activeTheme}`}
    >
      {themeIcon(activeTheme)}
      <span className='capitalize'>{activeTheme}</span>
    </button>
  );
}
