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
interface GeniusAuthExchangeOptions {
    code: string;
    codeVerifier: string;
    clientId: string;
    redirectUri: string;
    tokenEndpoint?: string;
}
interface GeniusAuthUser {
    sub: string;
    email?: string;
    emailVerified?: boolean;
    name?: string;
    geniusId?: string;
    phone?: string;
    phoneVerified?: boolean;
    userType?: string;
    roles?: string[];
}
interface GeniusAuthSession {
    accessToken: string;
    idToken: string;
    refreshToken: string;
    expiresAt: number;
    scope: string;
    user: GeniusAuthUser;
}
declare class GeniusAuth {
    static login(options: GeniusAuthLoginOptions): Promise<void>;
    static handleCallback(): GeniusAuthAuthorizationResult | null;
    static exchangeToken(options: GeniusAuthExchangeOptions): Promise<GeniusAuthSession>;
    static getUser(): GeniusAuthUser | null;
    static getAccessToken(): Promise<string | null>;
    static logout(options?: {
        endSessionEndpoint?: string;
        postLogoutRedirectUri?: string;
    }): void;
    private static requestTokens;
    private static storeSession;
    private static readSession;
    private static decodeUser;
    private static base64UrlDecode;
    private static createPendingAuthorization;
    private static awaitPopupResult;
    private static readPending;
    private static randomValue;
    private static challenge;
    private static base64Url;
}

export { GeniusAuth, type GeniusAuthAuthorizationResult, type GeniusAuthExchangeOptions, type GeniusAuthLoginOptions, type GeniusAuthSession, type GeniusAuthUser, GeniusAuth as default };
