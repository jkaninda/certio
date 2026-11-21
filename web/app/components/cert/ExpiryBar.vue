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
import type { Severity } from '~/types/api'

const props = defineProps<{
  notBefore: string
  notAfter: string
  daysRemaining: number
  severity: Severity
  /** Pre-computed by the API; recomputed here when absent. */
  percentElapsed?: number
}>()

const percent = computed(() => {
  if (props.percentElapsed !== undefined) return props.percentElapsed
  const start = new Date(props.notBefore).getTime()
  const end = new Date(props.notAfter).getTime()
  if (end <= start) return 100
  const elapsed = Date.now() - start
  return Math.min(100, Math.max(0, Math.round((elapsed / (end - start)) * 100)))
})
</script>

<template>
  <div class="expiry-bar" :class="`expiry-${severity}`" :title="`${percent}% of its lifetime elapsed`">
    <div class="expiry-bar-fill" :style="{ width: `${percent}%` }" />
  </div>
</template>
