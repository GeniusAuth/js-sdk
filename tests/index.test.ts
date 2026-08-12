import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import GeniusAuth, { GeniusAuth as NamedGeniusAuth } from '../src/index.js';

describe('GeniusAuth', () => {
    it('exports the default and named SDK class', () => {
        expect(GeniusAuth).toBe(NamedGeniusAuth);
    });
});

// In-memory sessionStorage polyfill — Node has no browser storage globals.
class MemoryStorage {
    private store = new Map<string, string>();
    getItem(key: string): string | null {
        return this.store.has(key) ? this.store.get(key)! : null;
    }
    setItem(key: string, value: string): void {
        this.store.set(key, value);
    }
    removeItem(key: string): void {
        this.store.delete(key);
    }
    clear(): void {
        this.store.clear();
    }
}

// Builds a JWT with the same claim shape geniusauth's OidcController::tokens() issues.
// Signature is a dummy value — the SDK never verifies it client-side, only the server does.
function fakeIdToken(claims: Record<string, unknown>): string {
    const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const payload = base64UrlEncode(JSON.stringify(claims));
    return `${header}.${payload}.fake-signature`;
}

function base64UrlEncode(value: string): string {
    return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

describe('GeniusAuth session (token exchange, user, refresh)', () => {
    let storage: MemoryStorage;

    beforeEach(() => {
        storage = new MemoryStorage();
        vi.stubGlobal('sessionStorage', storage);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.restoreAllMocks();
    });

    const claims = {
        sub: 'user_alice_uuid',
        email: 'alice@example.test',
        email_verified: true,
        name: 'Alice',
        genius_id: '@2250700000000',
        phone: '+2250700000000',
        phone_verified: true,
        user_type: 'end_user',
        roles: [],
    };

    it('exchanges an authorization code for tokens and stores the session', async () => {
        const fetchMock = vi.fn().mockResolvedValue(
            new Response(
                JSON.stringify({
                    token_type: 'Bearer',
                    access_token: 'access-123',
                    id_token: fakeIdToken(claims),
                    refresh_token: 'refresh-abc',
                    expires_in: 900,
                    scope: 'openid profile email',
                }),
                { status: 200, headers: { 'Content-Type': 'application/json' } },
            ),
        );
        vi.stubGlobal('fetch', fetchMock);

        const session = await GeniusAuth.exchangeToken({
            code: 'auth-code-xyz',
            codeVerifier: 'verifier-xyz',
            clientId: 'genius-demo',
            redirectUri: 'https://app.example.test/callback',
        });

        // Correct request sent to /token
        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
        expect(url).toBe('https://auth.geniuspay.tech/token');
        const body = new URLSearchParams(init.body as string);
        expect(body.get('grant_type')).toBe('authorization_code');
        expect(body.get('code')).toBe('auth-code-xyz');
        expect(body.get('code_verifier')).toBe('verifier-xyz');
        expect(body.get('client_id')).toBe('genius-demo');

        // Tokens correctly parsed
        expect(session.accessToken).toBe('access-123');
        expect(session.refreshToken).toBe('refresh-abc');

        // ID token claims decoded into a usable user object
        expect(session.user.email).toBe('alice@example.test');
        expect(session.user.geniusId).toBe('@2250700000000');

        // Session persisted — this is what makes getUser()/getAccessToken() work afterwards
        expect(storage.getItem('geniusauth:session')).not.toBeNull();
    });

    it('returns the logged-in user after a token exchange, without a network call', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue(
                new Response(
                    JSON.stringify({
                        access_token: 'access-123',
                        id_token: fakeIdToken(claims),
                        refresh_token: 'refresh-abc',
                        expires_in: 900,
                        scope: 'openid profile email',
                    }),
                    { status: 200 },
                ),
            ),
        );

        await GeniusAuth.exchangeToken({
            code: 'auth-code-xyz',
            codeVerifier: 'verifier-xyz',
            clientId: 'genius-demo',
            redirectUri: 'https://app.example.test/callback',
        });

        const user = GeniusAuth.getUser();
        expect(user).not.toBeNull();
        expect(user?.name).toBe('Alice');
        expect(user?.geniusId).toBe('@2250700000000');
    });

    it('returns null for getUser() when no session exists', () => {
        expect(GeniusAuth.getUser()).toBeNull();
    });

    it('returns the cached access token when it is still valid', async () => {
        const fetchMock = vi.fn().mockResolvedValue(
            new Response(
                JSON.stringify({
                    access_token: 'access-123',
                    id_token: fakeIdToken(claims),
                    refresh_token: 'refresh-abc',
                    expires_in: 900,
                    scope: 'openid profile email',
                }),
                { status: 200 },
            ),
        );
        vi.stubGlobal('fetch', fetchMock);

        await GeniusAuth.exchangeToken({
            code: 'auth-code-xyz',
            codeVerifier: 'verifier-xyz',
            clientId: 'genius-demo',
            redirectUri: 'https://app.example.test/callback',
        });

        const token = await GeniusAuth.getAccessToken();

        expect(token).toBe('access-123');
        expect(fetchMock).toHaveBeenCalledTimes(1); // only the initial exchange — no refresh needed
    });

    it('silently refreshes the access token once it is expired', async () => {
        const fetchMock = vi
            .fn()
            // 1) initial exchange — issued already-expired for the test
            .mockResolvedValueOnce(
                new Response(
                    JSON.stringify({
                        access_token: 'access-123',
                        id_token: fakeIdToken(claims),
                        refresh_token: 'refresh-abc',
                        expires_in: -10,
                        scope: 'openid profile email',
                    }),
                    { status: 200 },
                ),
            )
            // 2) refresh call
            .mockResolvedValueOnce(
                new Response(
                    JSON.stringify({
                        access_token: 'access-456-refreshed',
                        id_token: fakeIdToken(claims),
                        refresh_token: 'refresh-def',
                        expires_in: 900,
                        scope: 'openid profile email',
                    }),
                    { status: 200 },
                ),
            );
        vi.stubGlobal('fetch', fetchMock);

        await GeniusAuth.exchangeToken({
            code: 'auth-code-xyz',
            codeVerifier: 'verifier-xyz',
            clientId: 'genius-demo',
            redirectUri: 'https://app.example.test/callback',
        });

        const token = await GeniusAuth.getAccessToken();

        expect(token).toBe('access-456-refreshed');
        expect(fetchMock).toHaveBeenCalledTimes(2);
        const [, refreshInit] = fetchMock.mock.calls[1] as [string, RequestInit];
        const refreshBody = new URLSearchParams(refreshInit.body as string);
        expect(refreshBody.get('grant_type')).toBe('refresh_token');
        expect(refreshBody.get('refresh_token')).toBe('refresh-abc');
    });

    it('clears the session on logout', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue(
                new Response(
                    JSON.stringify({
                        access_token: 'access-123',
                        id_token: fakeIdToken(claims),
                        refresh_token: 'refresh-abc',
                        expires_in: 900,
                        scope: 'openid profile email',
                    }),
                    { status: 200 },
                ),
            ),
        );

        await GeniusAuth.exchangeToken({
            code: 'auth-code-xyz',
            codeVerifier: 'verifier-xyz',
            clientId: 'genius-demo',
            redirectUri: 'https://app.example.test/callback',
        });
        expect(GeniusAuth.getUser()).not.toBeNull();

        GeniusAuth.logout();

        expect(GeniusAuth.getUser()).toBeNull();
    });

    it('rejects when the token endpoint returns an error', async () => {
        vi.stubGlobal(
            'fetch',
            vi.fn().mockResolvedValue(new Response('', { status: 400 })),
        );

        await expect(
            GeniusAuth.exchangeToken({
                code: 'bad-code',
                codeVerifier: 'verifier-xyz',
                clientId: 'genius-demo',
                redirectUri: 'https://app.example.test/callback',
            }),
        ).rejects.toThrow('GeniusAuth token request failed (400).');
    });
});
