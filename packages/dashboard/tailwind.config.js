/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        shield: {
          bg:           '#010812',
          'bg-2':       '#020f28',
          surface:      '#050d20',
          'surface-2':  '#071428',
          border:       '#0c2350',
          'border-hi':  '#1a4090',
          primary:      '#1562f0',
          'primary-d':  '#0040cc',
          'primary-l':  '#4d8fff',
          accent:       '#00ccff',
          'accent-dim': 'rgba(0,204,255,0.15)',
          text:         '#c0d4f0',
          'text-muted': '#4d6a9a',
          'text-dim':   '#1a2d4a',
        },
        severity: {
          critical: '#ff3344',
          high:     '#ff8844',
          medium:   '#ffcc00',
          low:      '#00ccff',
          info:     '#4d6a9a',
          safe:     '#00ff88',
        }
      },
      fontFamily: {
        title: ['Goldman', 'sans-serif'],
        sub:   ['Chakra Petch', 'sans-serif'],
        body:  ['Electrolize', 'sans-serif'],
        mono:  ['Chakra Petch', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '4px',
        sm:      '2px',
        md:      '4px',
        lg:      '4px',
        xl:      '4px',
        '2xl':   '4px',
        full:    '9999px',
      },
      backgroundImage: {
        'shield-gradient':  'linear-gradient(135deg, #010812 0%, #020f28 50%, #0040cc 100%)',
        'primary-gradient': 'linear-gradient(135deg, #003399 0%, #1562f0 100%)',
        'card-gradient':    'linear-gradient(145deg, #050d20 0%, #071428 100%)',
        'grid-lines':       'linear-gradient(rgba(21,98,240,0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(21,98,240,0.07) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid': '64px 64px',
      },
      boxShadow: {
        'shield':    '0 0 40px rgba(21, 98, 240, 0.25)',
        'shield-lg': '0 0 60px rgba(21, 98, 240, 0.35)',
        'glow':      '0 4px 20px rgba(21, 98, 240, 0.45)',
        'card':      '0 16px 48px rgba(21, 98, 240, 0.18)',
      },
      letterSpacing: {
        widest: '0.25em',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float':      'float 6s ease-in-out infinite',
        'scan':       'scan 5s ease-in-out infinite',
        'breathe':    'breathe 4s ease-in-out infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%':      { transform: 'translateY(-8px)' },
        },
        scan: {
          '0%':   { top: '-2px', opacity: '0' },
          '5%':   { opacity: '1' },
          '95%':  { opacity: '0.6' },
          '100%': { top: '100%', opacity: '0' },
        },
        breathe: {
          '0%, 100%': { transform: 'scale(1)',    opacity: '0.5' },
          '50%':      { transform: 'scale(1.04)', opacity: '1' },
        },
      }
    }
  },
  plugins: [],
}
