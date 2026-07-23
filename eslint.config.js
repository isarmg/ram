import globals from "globals";

const safetyRules = {
  "eqeqeq": ["error", "always"],
  "no-eval": "error",
  "no-implied-eval": "error",
  "no-new-func": "error",
  "no-script-url": "error",
  "no-undef": "error",
};

export default [
  { ignores: ["node_modules/**", "target/**"] },
  {
    files: ["web/**/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: globals.browser,
    },
    rules: safetyRules,
  },
  {
    files: [
      "scripts/**/*.mjs",
      "tests/**/*.js",
      "eslint.config.js",
      "playwright.config.js",
      "vitest.config.js",
    ],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: globals.node,
    },
    rules: safetyRules,
  },
];
