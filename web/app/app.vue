<script setup lang="ts">
import { onMounted } from 'vue'
import { useThemeStore } from '~/stores/theme'
import { useAuthStore } from '~/stores/auth'

const theme = useThemeStore()
const auth = useAuthStore()

onMounted(async () => {
  theme.init()
  // Restore the session from the HttpOnly cookie so a reload does not bounce
  // the user back to the login screen.
  await auth.restore()
})
</script>

<template>
  <div>
    <NuxtLayout>
      <NuxtPage />
    </NuxtLayout>
    <ToastHost />
  </div>
</template>
