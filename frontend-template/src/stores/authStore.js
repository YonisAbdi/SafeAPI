import { reactive } from 'vue'
import { getUserEmailFromToken } from '../utils/decodeToken'

export const auth = reactive({
    isLoggedIn: !!localStorage.getItem('token'),
    email: getUserEmailFromToken()
})

export function login(token) {
    localStorage.setItem('token', token)
    auth.isLoggedIn = true
    auth.email = getUserEmailFromToken()
}

export function logout() {
    localStorage.removeItem('token')
    localStorage.removeItem('userId')
    auth.isLoggedIn = false
    auth.email = null
}
