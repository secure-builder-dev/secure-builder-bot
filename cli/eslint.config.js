// ESLint flat config: typescript-eslint's type-aware recommended set plus eslint-plugin-security,
// with warnings failing the run (--max-warnings 0 in package.json), the same as adapter-gitlab's.
// No file carries a suppression comment (CONSTRAINTS.md floor). One rule is off, with the reason.
import tseslint from "typescript-eslint";
import security from "eslint-plugin-security";

export default tseslint.config(
  { ignores: ["node_modules/", "coverage/"] },
  ...tseslint.configs.recommendedTypeChecked,
  security.configs.recommended,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
  },
  {
    rules: {
      // init writes the setup files into the repository the user ran it in, and run reads the
      // receipt core wrote there: every fs call takes a path under the repository root found at
      // run time. The rule would flag each one and say nothing a reviewer does not already know.
      "security/detect-non-literal-fs-filename": "off",
    },
  },
  {
    files: ["eslint.config.js", "vitest.config.ts", "bin/*.js"],
    ...tseslint.configs.disableTypeChecked,
  },
);
