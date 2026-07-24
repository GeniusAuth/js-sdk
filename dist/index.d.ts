interface GeniusAuthLoginOptions {
    authorizationEndpoint?: string;
    clientId: string;
    redirectUri: string;
    scope?: string;
    popup?: boolean;
    success(result: GeniusAuthAuthorizationResult): void;
    error(error: Error): void;
}
interface GeniusAuthAuthorizationResult {
    code: string;
    state: string;
    codeVerifier: string;
}
declare class GeniusAuth {
    static login(options: GeniusAuthLoginOptions): Promise<void>;
    static handleCallback(): GeniusAuthAuthorizationResult | null;
    static logout(options?: {
        endSessionEndpoint?: string;
        postLogoutRedirectUri?: string;
    }): void;
    private static createPendingAuthorization;
    private static awaitPopupResult;
    private static readPending;
    private static randomValue;
    private static challenge;
    private static base64Url;
}

export { GeniusAuth, type GeniusAuthAuthorizationResult, type GeniusAuthLoginOptions, GeniusAuth as default };
