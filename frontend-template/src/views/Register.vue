<template>
    <div>
        <h2>Registrera</h2>
        <input v-model="email" placeholder="Email" />
        <input v-model="password" placeholder="Lösenord" type="password" />

        <p v-if="successMessage" style="color: green">{{ successMessage }}</p>
        <p v-if="errorMessage" style="color: red">{{ errorMessage }}</p>

        <button @click="register">Registrera</button>

        <p>Har du ett konto? <router-link to="/login">Logga in</router-link></p>
    </div>
</template>

<script setup>
    import { ref } from 'vue'
    import axios from 'axios'
    import { useRouter } from 'vue-router'

    const email = ref('')
    const password = ref('')
    const successMessage = ref('')
    const errorMessage = ref('')
    const router = useRouter()

    const register = async () => {
        successMessage.value = ''
        errorMessage.value = ''

        try {
            await axios.post('/api/auth/register', {
                email: email.value,
                password: password.value
            })
            successMessage.value = 'Registrering lyckades! Du omdirigeras till inloggning...'
            setTimeout(() => {
                router.push('/login')
            }, 2000)
        } catch (err) {
            console.error('Registrering misslyckades:', err.response?.data || err.message)
            errorMessage.value = 'Registrering misslyckades – e-post kan redan vara registrerad.'
        }
    }
</script>

<style scoped>
    input {
        padding: 10px;
        margin-bottom: 10px;
        font-size: 16px;
        display: block;
        width: 100%;
        max-width: 300px;
        margin-left: auto;
        margin-right: auto;
    }

    button {
        padding: 10px 20px;
        font-size: 16px;
        display: block;
        margin: 0 auto;
    }
</style>
