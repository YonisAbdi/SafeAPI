export function getUserEmailFromToken() {
    const token = localStorage.getItem('token')
    if (!token) return null

    try {
        const payload = JSON.parse(atob(token.split('.')[1]))
        return payload.sub || null  // 'sub' innehåller e-post enligt din JWT
    } catch (error) {
        console.error('Kunde inte läsa token:', error)
        return null
    }
}
