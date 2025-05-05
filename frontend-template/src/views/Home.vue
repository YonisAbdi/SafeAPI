<template>
    <div class="home-content">
        <h1>Välkommen till Säker Inloggning</h1>
        <p v-if="auth.isLoggedIn">
            Du är nu inloggad som <strong>{{ auth.email }}</strong>. Välkommen!
        </p>
        <p v-else>
            Logga in eller registrera dig för att komma vidare.
        </p>
    </div>
</template>

<script setup>
    import { auth } from '../stores/authStore.js'
</script>

<style scoped>
    .home-content {
        text-align: center;
        margin-top: 5rem;
    }
</style>
