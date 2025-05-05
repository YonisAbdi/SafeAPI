<template>
    <div>
        <h2>Logga in</h2>
        <input v-model="email" placeholder="Email" />
        <input v-model="password" placeholder="Lösenord" type="password" />

        <p v-if="successMessage" style="color: green">{{ successMessage }}</p>
        <p v-if="errorMessage" style="color: red">{{ errorMessage }}</p>

        <button @click="handleLogin">Logga in</button>
    </div>
</template>

<script setup>
    import { ref } from 'vue'
    import axios from 'axios'
    import { useRouter } from 'vue-router'
    import { login as loginToStore } from '../stores/authStore'

    const email = ref('')
    const password = ref('')
    const successMessage = ref('')
    const errorMessage = ref('')
    const router = useRouter()

    const handleLogin = async () => {
        successMessage.value = ''
        errorMessage.value = ''

        try {
            const res = await axios.post('/api/auth/login', {
                email: email.value,
                password: password.value
            })

            if (res.data.requires2FA) {
                localStorage.setItem('userId', res.data.userId)
                successMessage.value = 'Verifieringskod har skickats till din e-post.'
                setTimeout(() => {
                    router.push('/verify')
                }, 1500)

            } else if (res.data.mustEnable2FA) {
                localStorage.setItem('userId', res.data.userId)
                loginToStore(res.data.token) // 👈 Sparar token och uppdaterar state
                successMessage.value = 'Du måste aktivera 2FA innan du kan fortsätta.'
                setTimeout(() => {
                    router.push('/enable-2fa')
                }, 1500)

            } else if (res.data.token) {
                loginToStore(res.data.token) // 👈 Direkt login utan 2FA
                router.push('/thankyou')
            } else {
                errorMessage.value = 'Oväntat svar från servern.'
            }

        } catch (err) {
            console.error('Inloggning misslyckades:', err.response?.data || err.message)
            errorMessage.value = err.response?.data || 'Fel vid inloggning – kontrollera e-post/lösenord eller att API:et körs.'
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
    }
</style>
