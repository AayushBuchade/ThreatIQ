/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0f1d',
          surface: '#111827',
          panel: '#1e293b',
          border: '#334155',
          accent: '#06b6d4',
          cyan: '#22d3ee',
          green: '#10b981',
          red: '#ef4444',
          amber: '#f59e0b',
          purple: '#8b5cf6'
        }
      }
    },
  },
  plugins: [],
}

