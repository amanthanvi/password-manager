import js from '@eslint/js'
import globals from 'globals'
import svelte from 'eslint-plugin-svelte'
import tseslint from 'typescript-eslint'

export default [
  {
    ignores: ['dist/**', 'dist-electron/**', 'node_modules/**']
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  ...svelte.configs['flat/recommended'],
  {
    files: ['**/*.{js,mjs,cjs,ts,svelte}'],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node
      }
    }
  },
  {
    files: ['**/*.test.ts'],
    languageOptions: {
      globals: {
        ...globals.vitest
      }
    }
  }
]
