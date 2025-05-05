<template>
    <nav class="navbar">
        <router-link to="/">Hem</router-link>

        <template v-if="!auth.isLoggedIn">
            <router-link to="/login">Logga in</router-link>
            <router-link to="/register">Registrera</router-link>
        </template>

        <template v-else>
            <span>Inloggad som: {{ auth.email }}</span>

            <template v-if="auth.email === 'yonisabdi.jobb@gmail.com'">
                <router-link to="/admin">Adminpanel</router-link>
            </template>

            <button @click="handleLogout">Logga ut</button>
        </template>
    </nav>
</template>

<script setup>
    import { auth, logout } from '../stores/authStore'
    import { useRouter } from 'vue-router'

    const router = useRouter()

    const handleLogout = () => {
        logout()
        router.push('/login')
    }
</script>

<style scoped>
    .navbar {
        display: flex;
        justify-content: center;
        gap: 20px;
        background-color: #f3f3f3;
        padding: 10px;
        font-weight: bold;
    }

    button {
        cursor: pointer;
        background: none;
        border: none;
        color: blue;
        text-decoration: underline;
        font-weight: bold;
    }
</style>
