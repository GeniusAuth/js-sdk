import GeniusAuth from '@geniusauth/js';

export function App() {
    const signIn = () => {
        void GeniusAuth.login({
            clientId: 'your_client_id',
            redirectUri: `${window.location.origin}/callback`,
            success: (result) => console.log(result),
            error: console.error,
        });
    };

    return <button onClick={signIn}>Continue with GeniusAuth</button>;
}
