<template>
    <div class="verify-container">
        <h2>Verifiera 2FA</h2>
        <input v-model="code" placeholder="Skriv in 2FA-kod" />

        <p v-if="errorMessage" style="color: red">{{ errorMessage }}</p>
        <p v-if="successMessage" style="color: green">{{ successMessage }}</p>

        <button @click="verify">Verifiera</button>
    </div>
</template>

<script setup>
    import { ref } from 'vue'
    import axios from 'axios'
    import { useRouter } from 'vue-router'
    import { login as storeLogin } from '../stores/authStore'

    const code = ref('')
    const errorMessage = ref('')
    const successMessage = ref('')
    const router = useRouter()
    const userId = localStorage.getItem('userId')

    const verify = async () => {
        errorMessage.value = ''
        successMessage.value = ''

        try {
            const res = await axios.post('/api/auth/verify-2fa', {
                userId,
                code: code.value
            })

            if (res.data.token) {
                storeLogin(res.data.token)
                localStorage.removeItem('userId') // inte längre nödvändigt efter inloggning
                successMessage.value = 'Verifiering lyckades!'
                setTimeout(() => {
                    router.push('/') // omdirigera till startsidan
                }, 1000)
            } else {
                errorMessage.value = 'Oväntat svar från servern.'
            }

        } catch (err) {
            errorMessage.value = 'Felaktig kod eller något gick fel.'
            console.error(err)
        }
    }
</script>

<style scoped>
    .verify-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 1rem;
    }

    input {
        padding: 10px;
        font-size: 16px;
    }

    button {
        padding: 10px 20px;
        font-size: 16px;
    }
</style>
