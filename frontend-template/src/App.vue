<template>
    <div>
        <NavBar />
        <div class="app-wrapper">
            <router-view />
        </div>
    </div>
</template>

<script setup>
    import NavBar from './components/NavBar.vue'
</script>

<style>
    body {
        margin: 0;
        font-family: Arial, sans-serif;
    }

    .app-wrapper {
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 85vh;
    }
</style>
