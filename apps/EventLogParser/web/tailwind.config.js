/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        panel: "#0f172a",
        panelAccent: "#13213c",
        accent: "#38bdf8",
        danger: "#f87171",
        primary: "#0ea5e9",
        muted: "#9fb0c7"
      }
    }
  },
  darkMode: "class",
  plugins: []
};
