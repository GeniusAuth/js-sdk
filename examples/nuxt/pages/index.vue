<script setup lang="ts">
import GeniusAuth from '@geniusauth/js';

function signIn() {
    void GeniusAuth.login({
        clientId: 'your_client_id',
        redirectUri: `${window.location.origin}/auth/callback`,
        success: (result) => console.log(result),
        error: console.error,
    });
}
</script>

<template>
    <button @click="signIn">Continue with GeniusAuth</button>
</template>
