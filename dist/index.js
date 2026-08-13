// src/index.ts
var storagePrefix = "geniusauth:authorization:";
var sessionStorageKey = "geniusauth:session";
var defaultAuthorizationEndpoint = "https://auth.geniuspay.tech/authorize";
var defaultTokenEndpoint = "https://auth.geniuspay.tech/token";
var refreshLeewaySeconds = 30;
var GeniusAuth = class {
  static async login(options) {
    try {
      const pending = await this.createPendingAuthorization(options.redirectUri);
      const url = new URL(options.authorizationEndpoint ?? defaultAuthorizationEndpoint);
      url.search = new URLSearchParams({
        client_id: options.clientId,
        redirect_uri: options.redirectUri,
        response_type: "code",
        scope: options.scope ?? "openid profile email",
        state: pending.state,
        nonce: this.randomValue(32),
        code_challenge: await this.challenge(pending.codeVerifier),
        code_challenge_method: "S256"
      }).toString();
      if (options.popup !== false) {
        const popup = window.open(url, "geniusauth", "popup=yes,width=480,height=720");
        if (popup) {
          const result = await this.awaitPopupResult(pending, popup);
          options.success(result);
          return;
        }
      }
      window.location.assign(url);
    } catch (error) {
      options.error(error instanceof Error ? error : new Error("GeniusAuth login failed."));
    }
  }
  static handleCallback() {
    const url = new URL(window.location.href);
    const error = url.searchParams.get("error");
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const host = window.opener ?? (window.parent !== window ? window.parent : null);
    if (host) {
      host.postMessage(
        error ? { type: "geniusauth:callback", error, state } : { type: "geniusauth:callback", result: { code, state } },
        url.origin
      );
      if (window.opener) {
        window.close();
      }
      return null;
    }
    if (error) {
      throw new Error(error);
    }
    if (!code || !state) {
      return null;
    }
    const pending = this.readPending(state);
    if (!pending || pending.redirectUri !== `${url.origin}${url.pathname}`) {
      throw new Error("Invalid GeniusAuth authorization response.");
    }
    sessionStorage.removeItem(storagePrefix + state);
    return { code, state, codeVerifier: pending.codeVerifier };
  }
  /**
   * Silent SSO — checks for an existing GeniusAuth session without any
   * visible redirect or popup, via a hidden iframe + `prompt=none`.
   * Resolves the authorization result if the user already has an active
   * session (so the caller can exchangeToken() right away), or `null` if
   * they don't (or the check times out) — never rejects.
   */
  static async checkSession(options) {
    const pending = await this.createPendingAuthorization(options.redirectUri);
    const url = new URL(options.authorizationEndpoint ?? defaultAuthorizationEndpoint);
    url.search = new URLSearchParams({
      client_id: options.clientId,
      redirect_uri: options.redirectUri,
      response_type: "code",
      scope: options.scope ?? "openid profile email",
      state: pending.state,
      nonce: this.randomValue(32),
      code_challenge: await this.challenge(pending.codeVerifier),
      code_challenge_method: "S256",
      prompt: "none"
    }).toString();
    return new Promise((resolve) => {
      const iframe = document.createElement("iframe");
      iframe.style.display = "none";
      iframe.setAttribute("aria-hidden", "true");
      const finish = (result) => {
        window.clearTimeout(timeout);
        window.removeEventListener("message", onMessage);
        iframe.remove();
        resolve(result);
      };
      const timeout = window.setTimeout(() => finish(null), options.timeoutMs ?? 6e3);
      const onMessage = (event) => {
        if (event.origin !== new URL(pending.redirectUri).origin || event.data?.type !== "geniusauth:callback") {
          return;
        }
        sessionStorage.removeItem(storagePrefix + pending.state);
        if (event.data.error) {
          finish(null);
          return;
        }
        const result = event.data.result;
        if (result.state !== pending.state) {
          finish(null);
          return;
        }
        finish({ ...result, codeVerifier: pending.codeVerifier });
      };
      window.addEventListener("message", onMessage);
      iframe.src = url.toString();
      document.body.appendChild(iframe);
    });
  }
  static async exchangeToken(options) {
    const tokenEndpoint = options.tokenEndpoint ?? defaultTokenEndpoint;
    const session = await this.requestTokens(tokenEndpoint, {
      grant_type: "authorization_code",
      client_id: options.clientId,
      code: options.code,
      redirect_uri: options.redirectUri,
      code_verifier: options.codeVerifier
    });
    this.storeSession(session, options.clientId, tokenEndpoint);
    return session;
  }
  static getUser() {
    const stored = this.readSession();
    return stored?.user ?? null;
  }
  static async getAccessToken() {
    const stored = this.readSession();
    if (!stored) {
      return null;
    }
    if (Date.now() < stored.expiresAt - refreshLeewaySeconds * 1e3) {
      return stored.accessToken;
    }
    try {
      const session = await this.requestTokens(stored.tokenEndpoint, {
        grant_type: "refresh_token",
        client_id: stored.clientId,
        refresh_token: stored.refreshToken
      });
      this.storeSession(session, stored.clientId, stored.tokenEndpoint);
      return session.accessToken;
    } catch {
      sessionStorage.removeItem(sessionStorageKey);
      return null;
    }
  }
  static logout(options = {}) {
    sessionStorage.removeItem(sessionStorageKey);
    if (!options.endSessionEndpoint) {
      return;
    }
    const url = new URL(options.endSessionEndpoint);
    if (options.postLogoutRedirectUri) {
      url.searchParams.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
    }
    window.location.assign(url);
  }
  static async requestTokens(tokenEndpoint, body) {
    const response = await fetch(tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(body).toString()
    });
    if (!response.ok) {
      throw new Error(`GeniusAuth token request failed (${response.status}).`);
    }
    const payload = await response.json();
    return {
      accessToken: payload.access_token,
      idToken: payload.id_token,
      refreshToken: payload.refresh_token,
      expiresAt: Date.now() + payload.expires_in * 1e3,
      scope: payload.scope,
      user: this.decodeUser(payload.id_token)
    };
  }
  static storeSession(session, clientId, tokenEndpoint) {
    const stored = { ...session, clientId, tokenEndpoint };
    sessionStorage.setItem(sessionStorageKey, JSON.stringify(stored));
  }
  static readSession() {
    const raw = sessionStorage.getItem(sessionStorageKey);
    if (!raw) {
      return null;
    }
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }
  static decodeUser(idToken) {
    const [, payload] = idToken.split(".");
    if (!payload) {
      throw new Error("GeniusAuth received a malformed ID token.");
    }
    const claims = JSON.parse(this.base64UrlDecode(payload));
    return {
      sub: String(claims.sub),
      email: typeof claims.email === "string" ? claims.email : void 0,
      emailVerified: typeof claims.email_verified === "boolean" ? claims.email_verified : void 0,
      name: typeof claims.name === "string" ? claims.name : void 0,
      geniusId: typeof claims.genius_id === "string" ? claims.genius_id : void 0,
      phone: typeof claims.phone === "string" ? claims.phone : void 0,
      phoneVerified: typeof claims.phone_verified === "boolean" ? claims.phone_verified : void 0,
      userType: typeof claims.user_type === "string" ? claims.user_type : void 0,
      roles: Array.isArray(claims.roles) ? claims.roles : void 0
    };
  }
  static base64UrlDecode(value) {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(value.length + (4 - value.length % 4) % 4, "=");
    return decodeURIComponent(
      atob(base64).split("").map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("")
    );
  }
  static async createPendingAuthorization(redirectUri) {
    const pending = {
      state: this.randomValue(32),
      codeVerifier: this.randomValue(64),
      redirectUri,
      createdAt: Date.now()
    };
    sessionStorage.setItem(storagePrefix + pending.state, JSON.stringify(pending));
    return pending;
  }
  static awaitPopupResult(pending, popup) {
    return new Promise((resolve, reject) => {
      const timeout = window.setTimeout(
        () => finish(new Error("GeniusAuth popup timed out.")),
        3e5
      );
      const interval = window.setInterval(() => {
        if (popup.closed) {
          finish(new Error("GeniusAuth popup was closed."));
        }
      }, 500);
      const finish = (error, result) => {
        window.clearTimeout(timeout);
        window.clearInterval(interval);
        window.removeEventListener("message", onMessage);
        if (error) {
          reject(error);
        } else if (result) {
          resolve(result);
        }
      };
      const onMessage = (event) => {
        if (event.origin !== new URL(pending.redirectUri).origin || event.data?.type !== "geniusauth:callback") {
          return;
        }
        if (event.data.error) {
          finish(new Error(event.data.error));
          return;
        }
        const result = event.data.result;
        if (result.state !== pending.state) {
          finish(new Error("Invalid GeniusAuth popup response."));
          return;
        }
        sessionStorage.removeItem(storagePrefix + pending.state);
        finish(void 0, { ...result, codeVerifier: pending.codeVerifier });
      };
      window.addEventListener("message", onMessage);
    });
  }
  static readPending(state) {
    const value = sessionStorage.getItem(storagePrefix + state);
    if (!value) {
      return null;
    }
    const pending = JSON.parse(value);
    if (Date.now() - pending.createdAt > 3e5) {
      sessionStorage.removeItem(storagePrefix + state);
      return null;
    }
    return pending;
  }
  static randomValue(byteLength) {
    const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
    return this.base64Url(bytes);
  }
  static async challenge(verifier) {
    return this.base64Url(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))
      )
    );
  }
  static base64Url(bytes) {
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
};
var index_default = GeniusAuth;
export {
  GeniusAuth,
  index_default as default
};
