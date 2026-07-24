import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
    { ignores: ['dist/**', 'coverage/**', 'node_modules/**'] },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    {
        languageOptions: {
            globals: {
                URL: 'readonly',
                URLSearchParams: 'readonly',
                TextEncoder: 'readonly',
                btoa: 'readonly',
                crypto: 'readonly',
                sessionStorage: 'readonly',
                window: 'readonly',
            },
        },
        rules: {
            '@typescript-eslint/consistent-type-definitions': ['error', 'interface'],
        },
    },
);
