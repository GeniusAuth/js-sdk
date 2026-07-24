// src/index.ts
var storagePrefix = "geniusauth:authorization:";
var defaultAuthorizationEndpoint = "https://auth.geniuspay.tech/authorize";
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
    if (error) {
      throw new Error(error);
    }
    if (!code || !state) {
      return null;
    }
    if (window.opener) {
      window.opener.postMessage(
        { type: "geniusauth:callback", result: { code, state } },
        url.origin
      );
      window.close();
      return null;
    }
    const pending = this.readPending(state);
    if (!pending || pending.redirectUri !== `${url.origin}${url.pathname}`) {
      throw new Error("Invalid GeniusAuth authorization response.");
    }
    sessionStorage.removeItem(storagePrefix + state);
    return { code, state, codeVerifier: pending.codeVerifier };
  }
  static logout(options = {}) {
    if (!options.endSessionEndpoint) {
      return;
    }
    const url = new URL(options.endSessionEndpoint);
    if (options.postLogoutRedirectUri) {
      url.searchParams.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
    }
    window.location.assign(url);
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
