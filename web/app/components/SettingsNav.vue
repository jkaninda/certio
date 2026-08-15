<script setup lang="ts">
import { computed } from 'vue'
import { useAuthStore } from '~/stores/auth'

const route = useRoute()
const auth = useAuthStore()

const tabs = computed(() =>
  [
    { path: '/settings', label: 'General', adminOnly: true },
    { path: '/settings/security', label: 'Security', adminOnly: false },
    { path: '/settings/users', label: 'Users', adminOnly: true },
    { path: '/settings/tokens', label: 'API tokens', adminOnly: false },
    { path: '/settings/notifications', label: 'Notifications', adminOnly: true },
    { path: '/settings/deployments', label: 'Deployments', adminOnly: true },
    { path: '/settings/acme', label: 'ACME', adminOnly: true },
  ].filter((tab) => !tab.adminOnly || auth.isAdmin),
)
</script>

<template>
  <div class="tabs">
    <button
      v-for="tab in tabs"
      :key="tab.path"
      class="tab"
      :class="{ active: route.path === tab.path }"
      @click="navigateTo(tab.path)"
    >
      {{ tab.label }}
    </button>
  </div>
</template>
