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
        accent: "#fb923c",
        danger: "#f87171",
        primary: "#ea580c",
        muted: "#9fb0c7"
      }
    }
  },
  darkMode: "class",
  plugins: []
};
