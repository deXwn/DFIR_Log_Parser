/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        panel: "#111111",
        panelAccent: "#1a1a1a",
        accent: "#00b7ff",
        danger: "#cc0000",
        primary: "#cc0000",
        muted: "#b0b0b0"
      }
    }
  },
  darkMode: "class",
  plugins: []
};
