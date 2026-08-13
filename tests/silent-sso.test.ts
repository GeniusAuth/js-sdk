// @vitest-environment happy-dom
//
// checkSession() drives a real hidden <iframe> and listens for window
// `message` events, so it needs an actual DOM — the rest of the suite runs
// against plain Node (see index.test.ts) since it only touches
// sessionStorage/fetch. happy-dom gives us document/window/postMessage
// without pulling in a full browser.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import GeniusAuth from '../src/index.js';

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

describe('GeniusAuth.checkSession (Silent SSO)', () => {
    let storage: MemoryStorage;

    beforeEach(() => {
        storage = new MemoryStorage();
        vi.stubGlobal('sessionStorage', storage);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.useRealTimers();
        document.querySelectorAll('iframe').forEach((el) => el.remove());
    });

    it('appends a hidden iframe pointed at /authorize with prompt=none', async () => {
        const promise = GeniusAuth.checkSession({
            clientId: 'genius-demo',
            redirectUri: 'https://app.example.test/callback',
            authorizationEndpoint: 'https://auth.geniuspay.tech/authorize',
        });

        // Let the async PKCE challenge computation resolve and the iframe mount
        // (happy-dom's own iframe network handling adds a tick or two of its own).
        await new Promise((r) => setTimeout(r, 50));

        const iframe = document.querySelector('iframe');
        expect(iframe).not.toBeNull();
        expect(iframe?.style.display).toBe('none');
        const src = new URL(iframe!.src);
        expect(src.origin + src.pathname).toBe('https://auth.geniuspay.tech/authorize');
        expect(src.searchParams.get('prompt')).toBe('none');
        expect(src.searchParams.get('client_id')).toBe('genius-demo');
        expect(src.searchParams.get('code_challenge_method')).toBe('S256');

        // Resolve the pending promise so the test doesn't leak a timer.
        window.dispatchEvent(
            new MessageEvent('message', {
                origin: 'https://app.example.test',
                data: { type: 'geniusauth:callback', error: 'login_required', state: src.searchParams.get('state') },
            }),
        );
        await promise;
    });

    it('resolves with the authorization result when the user already has a session', async () => {
        const promise = GeniusAuth.checkSession({
            clientId: 'genius-demo',
            redirectUri: 'https://app.example.test/callback',
            authorizationEndpoint: 'https://auth.geniuspay.tech/authorize',
        });
        await new Promise((r) => setTimeout(r, 50));

        const iframe = document.querySelector('iframe')!;
        const state = new URL(iframe.src).searchParams.get('state');

        window.dispatchEvent(
            new MessageEvent('message', {
                origin: 'https://app.example.test',
                data: { type: 'geniusauth:callback', result: { code: 'silent-code-123', state } },
            }),
        );

        const result = await promise;
        expect(result).not.toBeNull();
        expect(result?.code).toBe('silent-code-123');
        expect(result?.codeVerifier).toBeTruthy();

        // The iframe is cleaned up once the check settles.
        expect(document.querySelector('iframe')).toBeNull();
    });

    it('resolves null when the IdP reports login_required (no active session)', async () => {
        const promise = GeniusAuth.checkSession({
            clientId: 'genius-demo',
            redirectUri: 'https://app.example.test/callback',
        });
        await new Promise((r) => setTimeout(r, 0));

        const iframe = document.querySelector('iframe')!;
        const state = new URL(iframe.src).searchParams.get('state');

        window.dispatchEvent(
            new MessageEvent('message', {
                origin: 'https://app.example.test',
                data: { type: 'geniusauth:callback', error: 'login_required', state },
            }),
        );

        await expect(promise).resolves.toBeNull();
    });

    it('resolves null (never rejects) if the IdP never responds in time', async () => {
        vi.useFakeTimers();
        const promise = GeniusAuth.checkSession({
            clientId: 'genius-demo',
            redirectUri: 'https://app.example.test/callback',
            timeoutMs: 1000,
        });

        await vi.advanceTimersByTimeAsync(1000);
        await expect(promise).resolves.toBeNull();
    });

    it('ignores messages from an unrelated origin', async () => {
        const promise = GeniusAuth.checkSession({
            clientId: 'genius-demo',
            redirectUri: 'https://app.example.test/callback',
            timeoutMs: 300,
        });
        await new Promise((r) => setTimeout(r, 50));

        const iframe = document.querySelector('iframe')!;
        const state = new URL(iframe.src).searchParams.get('state');

        window.dispatchEvent(
            new MessageEvent('message', {
                origin: 'https://evil.example.test',
                data: { type: 'geniusauth:callback', result: { code: 'stolen', state } },
            }),
        );

        // Spoofed message is ignored — the check still only settles on timeout.
        await expect(promise).resolves.toBeNull();
    });
});
