import { createRouter, createWebHistory } from 'vue-router'

import Home from '../views/Home.vue'
import Login from '../views/Login.vue'
import Register from '../views/Register.vue'
import Verify2FA from '../views/Verify2FA.vue'
import ThankYou from '../views/ThankYou.vue'
import Enable2FA from '../views/Enable2FA.vue'
import AdminPanel from '../views/AdminPanel.vue'

const routes = [
    { path: '/', component: Home },
    { path: '/login', component: Login },
    { path: '/register', component: Register },
    { path: '/verify', component: Verify2FA },
    { path: '/thankyou', component: ThankYou, meta: { requiresAuth: true } },
    { path: '/enable-2fa', component: Enable2FA, meta: { requiresAuth: true } },
    { path: '/admin', component: AdminPanel, meta: { requiresAuth: true } },
    { path: '/:pathMatch(.*)*', redirect: '/' } // fallback till hemsidan
]

const router = createRouter({
    history: createWebHistory(),
    routes
})

//  Navigation guards
router.beforeEach((to, from, next) => {
    const token = localStorage.getItem('token')

    // Om användaren redan är inloggad, förhindra tillgång till login/register
    if ((to.path === '/login' || to.path === '/register') && token) {
        return next('/')
    }

    // Om route kräver autentisering men ingen token finns
    if (to.meta.requiresAuth && !token) {
        return next('/login')
    }

    next()
})

export default router
