<div align="center">

# GeniusAuth™ JavaScript SDK

### Passwordless identity for the web

**One Identity. Every Application. Zero Passwords.**

[![npm](https://img.shields.io/npm/v/@geniusauth/js?style=for-the-badge)](https://www.npmjs.com/package/@geniusauth/js)
[![CI](https://img.shields.io/github/actions/workflow/status/GeniusAuth/js-sdk/ci.yml?style=for-the-badge&label=CI)](https://github.com/GeniusAuth/js-sdk/actions)
[![License](https://img.shields.io/npm/l/@geniusauth/js?style=for-the-badge)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-ready-3178C6?style=for-the-badge)](https://www.typescriptlang.org/)

[Documentation](https://docs.geniusauth.com/js) · [Report a bug](https://github.com/GeniusAuth/js-sdk/issues) · [Request a feature](https://github.com/GeniusAuth/js-sdk/issues)

</div>

## Installation

```bash
npm install @geniusauth/js
```

## Quick Start

Start a sign-in flow from your browser application:

```ts
import GeniusAuth from '@geniusauth/js';

await GeniusAuth.login({
    clientId: 'your_client_id',
    redirectUri: `${window.location.origin}/auth/callback`,
    success: ({ code, codeVerifier }) => {
        // Exchange code and verifier only from your backend.
    },
    error: console.error,
});
```

By default, the SDK uses `https://auth.geniuspay.tech/authorize`. Configure your authorized redirect URI in the [GeniusAuth dashboard](https://docs.geniusauth.com).

## Callback Handling

Call `handleCallback()` on your redirect URI page when using full-page redirects:

```ts
const result = GeniusAuth.handleCallback();

if (result) {
    await fetch('/api/auth/genius/callback', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(result),
    });
}
```

The SDK validates the state and includes the PKCE verifier required for a server-side token exchange.

## Configuration

| Option                  | Required | Description                                           |
| ----------------------- | -------- | ----------------------------------------------------- |
| `clientId`              | Yes      | Your GeniusAuth application client ID.                |
| `redirectUri`           | Yes      | An allow-listed absolute callback URL.                |
| `authorizationEndpoint` | No       | Overrides the default authorize endpoint.             |
| `scope`                 | No       | Requested scopes; defaults to `openid profile email`. |
| `popup`                 | No       | Uses a popup unless explicitly set to `false`.        |
| `success`               | Yes      | Receives code, state, and PKCE verifier.              |
| `error`                 | Yes      | Receives a safe `Error` object.                       |

## API

| Method                        | Description                                             |
| ----------------------------- | ------------------------------------------------------- |
| `GeniusAuth.login(options)`   | Starts an OAuth 2.1 Authorization Code flow with PKCE.  |
| `GeniusAuth.handleCallback()` | Validates and returns callback data for redirect flows. |
| `GeniusAuth.logout(options)`  | Redirects to an optional OIDC end-session endpoint.     |

Find framework-specific integration guidance in the [documentation](https://docs.geniusauth.com/js).

## Security

The SDK creates a cryptographically random state and PKCE verifier, stores pending requests in session storage, and validates callback state before returning data. Exchange authorization codes on your backend; never expose client secrets in browser code. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Browser Support

Modern Chrome, Edge, Firefox, Safari, Brave, and Arc releases are supported. Applications require Web Crypto and session storage.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please use [Conventional Commits](https://www.conventionalcommits.org/) and run:

```bash
npm ci
npm run check
```

## License

GeniusAuth JavaScript SDK is open-sourced software licensed under the [MIT license](LICENSE).
