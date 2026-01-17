/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // oklch base scale
        base: {
          50: 'oklch(0.9867 0.0017 219.35)',
          100: 'oklch(0.9701 0.0035 220.38)',
          200: 'oklch(0.9292 0.0071 220.94)',
          300: 'oklch(0.8695 0.0105 222.21)',
          400: 'oklch(0.6386 0.0159 224.62)',
          500: 'oklch(0.5541 0.0212 225.44)',
          600: 'oklch(0.4463 0.0202 225.58)',
          700: 'oklch(0.373 0.0183 225.41)',
          800: 'oklch(0.2779 0.0162 226.51)',
          900: 'oklch(0.21 0.0139 227.92)',
          950: 'oklch(0.1324 0.0125 228.42)',
          1000: 'oklch(0.0822 0.0116 228.77)',
        },
        // CSS variable colors (use var() directly, not hsl())
        border: 'var(--border)',
        input: 'var(--input)',
        ring: 'var(--ring)',
        background: 'var(--background)',
        foreground: 'var(--foreground)',
        primary: {
          DEFAULT: 'var(--primary)',
          foreground: 'var(--primary-foreground)',
        },
        secondary: {
          DEFAULT: 'var(--secondary)',
          foreground: 'var(--secondary-foreground)',
        },
        destructive: {
          DEFAULT: 'var(--destructive)',
          foreground: 'var(--destructive-foreground)',
        },
        muted: {
          DEFAULT: 'var(--muted)',
          foreground: 'var(--muted-foreground)',
        },
        accent: {
          DEFAULT: 'var(--accent)',
          foreground: 'var(--accent-foreground)',
        },
        popover: {
          DEFAULT: 'var(--popover)',
          foreground: 'var(--popover-foreground)',
        },
        card: {
          DEFAULT: 'var(--card)',
          foreground: 'var(--card-foreground)',
        },
        // Status colors
        success: {
          DEFAULT: 'var(--success)',
          muted: 'var(--success-muted)',
          bg: 'var(--success-bg)',
          'bg-hover': 'var(--success-bg-hover)',
          border: 'var(--success-border)',
        },
        warning: 'var(--warning)',
        error: {
          DEFAULT: 'var(--error)',
          muted: 'var(--error-muted)',
          indicator: 'var(--error-indicator)',
        },
        info: 'var(--info)',
      },
      fontFamily: {
        display: ['Figtree', 'sans-serif'],
        text: ['Nunito', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
        brand: ['Orbitron', 'sans-serif'],
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      keyframes: {
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'slide-up': {
          '0%': { opacity: '0', transform: 'translateY(16px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'pulse-glow': {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.5', transform: 'scale(1.2)' },
        },
        'line-load': {
          '0%': { transform: 'scaleX(0)' },
          '100%': { transform: 'scaleX(1)' },
        },
        'section-load': {
          '0%': { opacity: '0', transform: 'translateY(16px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'page-load': {
          '0%': { width: '0%', opacity: '1' },
          '80%': { width: '100%', opacity: '1' },
          '100%': { width: '100%', opacity: '0' },
        },
      },
      animation: {
        'fade-in': 'fade-in 0.3s ease-out',
        'slide-up': 'slide-up 0.5s cubic-bezier(0.4, 0, 0.2, 1)',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'line-load': 'line-load 0.4s cubic-bezier(0.4, 0, 0.2, 1) forwards',
        'section-load': 'section-load 0.5s cubic-bezier(0.4, 0, 0.2, 1) forwards',
        'page-load': 'page-load 0.6s cubic-bezier(0.4, 0, 0.2, 1) forwards',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
}
