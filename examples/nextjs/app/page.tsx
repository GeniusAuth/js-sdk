'use client';

import GeniusAuth from '@geniusauth/js';

export default function Home() {
    const signIn = () => {
        void GeniusAuth.login({
            clientId: 'your_client_id',
            redirectUri: `${window.location.origin}/auth/callback`,
            success: (result) => console.log(result),
            error: console.error,
        });
    };

    return <button onClick={signIn}>Continue with GeniusAuth</button>;
}
