// ESLint flat config: typescript-eslint's recommended rules plus eslint-plugin-security's, on
// every TypeScript file in the package. No file carries a disable comment (CONSTRAINTS.md): a
// finding is fixed in the code. Two of the security plugin's rules are off, by decision, because
// they describe untyped JavaScript and would fire on every line of this module's job:
//   detect-non-literal-fs-filename — the publisher reads the run directory its caller names;
//   detect-object-injection — every computed key here is a TypeScript-checked union (GateName).
import security from 'eslint-plugin-security';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['node_modules/', 'coverage/'] },
  tseslint.configs.recommended,
  security.configs.recommended,
  {
    rules: {
      eqeqeq: 'error',
      'no-var': 'error',
      'prefer-const': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      'security/detect-non-literal-fs-filename': 'off',
      'security/detect-object-injection': 'off',
    },
  },
);
