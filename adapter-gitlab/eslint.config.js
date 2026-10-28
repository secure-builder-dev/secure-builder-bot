// ESLint flat config: typescript-eslint's type-aware recommended set plus eslint-plugin-security,
// with warnings failing the run (--max-warnings 0 in package.json). No file carries a suppression
// comment (CONSTRAINTS.md floor). One rule is off, with the reason beside it.
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
      // The publisher's job is to read the run directory core wrote, at a path given at run time,
      // and write the code quality report beside it: every fs call takes that path. The rule
      // would flag each one and say nothing a reviewer does not already know.
      "security/detect-non-literal-fs-filename": "off",
    },
  },
  {
    files: ["eslint.config.js", "vitest.config.ts"],
    ...tseslint.configs.disableTypeChecked,
  },
);
