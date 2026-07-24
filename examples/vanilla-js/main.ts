import GeniusAuth from '@geniusauth/js';

const callback = GeniusAuth.handleCallback();

if (callback) {
    await fetch('/api/auth/genius/callback', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(callback),
    });
}

document.querySelector<HTMLButtonElement>('#sign-in')?.addEventListener('click', () => {
    void GeniusAuth.login({
        clientId: 'your_client_id',
        redirectUri: `${window.location.origin}/callback`,
        success: (result) => console.log(result),
        error: console.error,
    });
});
