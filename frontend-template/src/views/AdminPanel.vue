<template>
    <div class="admin-container">
        <h2>Adminpanel – Godkänn användare</h2>
        <div v-if="successMessage" class="success-message">{{ successMessage }}</div>

        <ul v-if="users.length">
            <li v-for="user in users" :key="user.id">
                {{ user.email }}
                <button @click="approve(user.id)">Godkänn</button>
            </li>
        </ul>
        <p v-else>Inga användare att godkänna.</p>
    </div>
</template>

<script setup>
    import { ref, onMounted } from 'vue'
    import axios from 'axios'

    const users = ref([])
    const successMessage = ref('')

    const fetchUsers = async () => {
        try {
            const res = await axios.get('/api/admin/pending-users', {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            })
            users.value = res.data
        } catch (err) {
            console.error('Kunde inte hämta användare:', err)
        }
    }

    const approve = async (userId) => {
        try {
            await axios.post('/api/admin/confirm-user', JSON.stringify(userId), {
                headers: {
                    Authorization: `Bearer ${localStorage.getItem('token')}`,
                    'Content-Type': 'application/json'
                }
            })
            users.value = users.value.filter(u => u.id !== userId)
            successMessage.value = 'Användaren har bekräftats.'
            setTimeout(() => (successMessage.value = ''), 3000)
        } catch (err) {
            console.error('Godkännande misslyckades:', err)
        }
    }

    onMounted(fetchUsers)
</script>

<style scoped>
    .admin-container {
        padding: 20px;
        max-width: 600px;
        margin: auto;
    }

    button {
        margin-left: 10px;
        padding: 5px 10px;
    }

    .success-message {
        color: green;
        margin-bottom: 10px;
        font-weight: bold;
    }
</style>
