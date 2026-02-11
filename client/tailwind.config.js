/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        nexus: {
          dark: '#0a0a0f',
          card: '#13131f',
          accent: '#00d4ff',
          purple: '#7b2cbf',
        }
      }
    },
  },
  plugins: [],
}
