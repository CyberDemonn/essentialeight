/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        navy: {
          DEFAULT: '#1e3a5f',
          50: '#f0f5fb',
          100: '#dce8f5',
          700: '#1e3a5f',
          800: '#162d4a',
          900: '#0f1f35',
        },
      },
    },
  },
  plugins: [],
}
