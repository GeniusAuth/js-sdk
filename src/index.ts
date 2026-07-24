export interface GeniusAuthLoginOptions {
    authorizationEndpoint: string;
    clientId: string;
    redirectUri: string;
    scope?: string;
    popup?: boolean;
    success(result: GeniusAuthAuthorizationResult): void;
    error(error: Error): void;
}

export interface GeniusAuthAuthorizationResult {
    code: string;
    state: string;
    codeVerifier: string;
}

interface PendingAuthorization {
    state: string;
    codeVerifier: string;
    redirectUri: string;
    createdAt: number;
}

const storagePrefix = 'geniusauth:authorization:';

export class GeniusAuth {
    static async login(options: GeniusAuthLoginOptions): Promise<void> {
        try {
            const pending = await this.createPendingAuthorization(options.redirectUri);
            const url = new URL(options.authorizationEndpoint);
            url.search = new URLSearchParams({
                client_id: options.clientId,
                redirect_uri: options.redirectUri,
                response_type: 'code',
                scope: options.scope ?? 'openid profile email',
                state: pending.state,
                nonce: this.randomValue(32),
                code_challenge: await this.challenge(pending.codeVerifier),
                code_challenge_method: 'S256',
            }).toString();

            if (options.popup !== false) {
                const popup = window.open(url, 'geniusauth', 'popup=yes,width=480,height=720');
                if (popup) {
                    const result = await this.awaitPopupResult(pending, popup);
                    options.success(result);
                    return;
                }
            }

            window.location.assign(url);
        } catch (error) {
            options.error(error instanceof Error ? error : new Error('GeniusAuth login failed.'));
        }
    }

    static handleCallback(): GeniusAuthAuthorizationResult | null {
        const url = new URL(window.location.href);
        const error = url.searchParams.get('error');
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');

        if (error) {
            throw new Error(error);
        }
        if (!code || !state) {
            return null;
        }

        if (window.opener) {
            window.opener.postMessage({type: 'geniusauth:callback', result: {code, state}}, url.origin);
            window.close();
            return null;
        }

        const pending = this.readPending(state);
        if (!pending || pending.redirectUri !== `${url.origin}${url.pathname}`) {
            throw new Error('Invalid GeniusAuth authorization response.');
        }

        sessionStorage.removeItem(storagePrefix + state);

        return {code, state, codeVerifier: pending.codeVerifier};
    }

    static logout(options: {endSessionEndpoint?: string; postLogoutRedirectUri?: string} = {}): void {
        if (!options.endSessionEndpoint) {
            return;
        }
        const url = new URL(options.endSessionEndpoint);
        if (options.postLogoutRedirectUri) {
            url.searchParams.set('post_logout_redirect_uri', options.postLogoutRedirectUri);
        }
        window.location.assign(url);
    }

    private static async createPendingAuthorization(redirectUri: string): Promise<PendingAuthorization> {
        const pending = {
            state: this.randomValue(32),
            codeVerifier: this.randomValue(64),
            redirectUri,
            createdAt: Date.now(),
        };
        sessionStorage.setItem(storagePrefix + pending.state, JSON.stringify(pending));

        return pending;
    }

    private static awaitPopupResult(pending: PendingAuthorization, popup: Window): Promise<GeniusAuthAuthorizationResult> {
        return new Promise((resolve, reject) => {
            const timeout = window.setTimeout(() => finish(new Error('GeniusAuth popup timed out.')), 300000);
            const interval = window.setInterval(() => {
                if (popup.closed) {
                    finish(new Error('GeniusAuth popup was closed.'));
                }
            }, 500);
            const finish = (error?: Error, result?: GeniusAuthAuthorizationResult) => {
                window.clearTimeout(timeout);
                window.clearInterval(interval);
                window.removeEventListener('message', onMessage);
                if (error) {
                    reject(error);
                } else if (result) {
                    resolve(result);
                }
            };
            const onMessage = (event: MessageEvent) => {
                if (event.origin !== new URL(pending.redirectUri).origin || event.data?.type !== 'geniusauth:callback') {
                    return;
                }
                const result = event.data.result as Pick<GeniusAuthAuthorizationResult, 'code' | 'state'>;
                if (result.state !== pending.state) {
                    finish(new Error('Invalid GeniusAuth popup response.'));
                    return;
                }
                sessionStorage.removeItem(storagePrefix + pending.state);
                finish(undefined, {...result, codeVerifier: pending.codeVerifier});
            };
            window.addEventListener('message', onMessage);
        });
    }

    private static readPending(state: string): PendingAuthorization | null {
        const value = sessionStorage.getItem(storagePrefix + state);
        if (!value) {
            return null;
        }
        const pending = JSON.parse(value) as PendingAuthorization;
        if (Date.now() - pending.createdAt > 300000) {
            sessionStorage.removeItem(storagePrefix + state);
            return null;
        }

        return pending;
    }

    private static randomValue(byteLength: number): string {
        const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
        return this.base64Url(bytes);
    }

    private static async challenge(verifier: string): Promise<string> {
        return this.base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
    }

    private static base64Url(bytes: Uint8Array): string {
        return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }
}

export default GeniusAuth;
