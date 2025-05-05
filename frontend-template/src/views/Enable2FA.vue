<template>
    <div class="enable2fa-container">
        <h2>Aktivera tvåfaktorsautentisering (2FA)</h2>

        <p v-if="infoText">
            En kod har skickats till din mejl. Skriv in den nedan för att aktivera 2FA.
        </p>

        <input v-model="code" placeholder="Skriv in 2FA-kod" />

        <p v-if="errorMessage" style="color: red">{{ errorMessage }}</p>
        <p v-if="successMessage" style="color: green">{{ successMessage }}</p>

        <button @click="confirm2FA">Bekräfta</button>
    </div>
</template>

<script setup>
    import { ref } from 'vue'
    import axios from 'axios'
    import { useRouter } from 'vue-router'
    import { login as storeLogin } from '../stores/authStore'

    const router = useRouter()
    const code = ref('')
    const userId = localStorage.getItem('userId')
    const successMessage = ref('')
    const errorMessage = ref('')
    const infoText = ref(true)

    const confirm2FA = async () => {
        errorMessage.value = ''
        successMessage.value = ''

        try {
            const res = await axios.post('/api/auth/confirm-2fa-email', {
                userId,
                code: code.value
            })

            if (res.data.token) {
                storeLogin(res.data.token)
                localStorage.removeItem('userId')
                successMessage.value = '2FA har aktiverats och du är nu inloggad.'
                setTimeout(() => {
                    router.push('/')
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
    .enable2fa-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 1rem;
        max-width: 400px;
        margin: auto;
        text-align: center;
    }

    input {
        padding: 10px;
        font-size: 16px;
        width: 100%;
    }

    button {
        padding: 10px 20px;
        font-size: 16px;
    }
</style>
