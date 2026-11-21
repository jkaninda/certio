<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Certio - Self-signed PKI and TLS certificate management
  Copyright (C) 2026 Jonas Kaninda

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
-->

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
    { path: '/settings/oauth', label: 'Single sign-on', adminOnly: true },
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
