import globals from 'globals'
import pluginJs from '@eslint/js'
import tseslint from 'typescript-eslint'
import pluginNode from 'eslint-plugin-n'
import pluginImport from 'eslint-plugin-import'
import prettierRecommended from 'eslint-plugin-prettier/recommended'

export default [
  {
    ignores: ['node_modules/', 'dist/', '**/*.d.ts'],
  },
  {
    files: ['**/*.{js,ts}'],
  },
  { languageOptions: { globals: globals.node } },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: [
            'eslint.config.js',
            'test/utils/which-node-test.mjs',
            'vendor/build-common.ts',
            'vendor/seccomp/build.ts',
            'vendor/srt-win/build.ts',
            'vendor/java-proxy-agent/build.ts',
          ],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ['test/**/*.ts'],
    languageOptions: {
      parserOptions: {
        project: './tsconfig.test.json',
        projectService: false,
      },
    },
  },
  {
    plugins: {
      'eslint-plugin-n': pluginNode,
      import: pluginImport,
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          args: 'all',
          argsIgnorePattern: '^_',
          caughtErrors: 'all',
          caughtErrorsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          ignoreRestSiblings: true,
        },
      ],
      '@typescript-eslint/switch-exhaustiveness-check': [
        'error',
        {
          considerDefaultExhaustiveForUnions: true,
        },
      ],
      '@typescript-eslint/await-thenable': 'error',
      '@typescript-eslint/no-floating-promises': [
        'error',
        {
          ignoreVoid: true,
          ignoreIIFE: true,
        },
      ],
      '@typescript-eslint/consistent-type-imports': [
        'error',
        {
          prefer: 'type-imports',
          fixStyle: 'inline-type-imports',
        },
      ],
      eqeqeq: ['error', 'always'],
      'eslint-plugin-n/no-unsupported-features/es-builtins': [
        'error',
        {
          version: '>=20.11.0',
          ignores: [],
        },
      ],
      'eslint-plugin-n/no-unsupported-features/node-builtins': [
        'error',
        {
          version: '>=20.11.0',
          // Web-standard Request/Headers/ReadableStream and the
          // Readable.toWeb/fromWeb adapters are available since Node 18.0.0
          // (the rule flags them as experimental until 21–23) and stable in
          // Bun, which is SRT's primary runtime.
          ignores: [
            'Request',
            'Headers',
            'ReadableStream',
            'stream.Readable.toWeb',
            'stream.Readable.fromWeb',
            // Backported to ^20.11.0 and ^21.2.0; the rule's semver
            // intersection rejects `>=20.11.0` because that range
            // includes 21.0.x/22.0-22.15 which lack it.
            'import.meta.dirname',
          ],
        },
      ],
      'no-async-promise-executor': 'off',
      'import/no-cycle': [
        'warn',
        {
          maxDepth: 4,
          ignoreExternal: true,
          disableScc: true,
        },
      ],
    },
    settings: {
      'import/parsers': {
        '@typescript-eslint/parser': ['.ts'],
      },
      'import/resolver': {
        typescript: {
          project: './tsconfig.json',
        },
      },
    },
    linterOptions: {
      reportUnusedDisableDirectives: false,
    },
  },
  prettierRecommended,
]
