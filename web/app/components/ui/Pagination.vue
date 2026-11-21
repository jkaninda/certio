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

const props = defineProps<{
  page: number
  limit: number
  total: number
  totalPages: number
}>()

const emit = defineEmits<{ 'update:page': [value: number] }>()

const from = computed(() => (props.total === 0 ? 0 : (props.page - 1) * props.limit + 1))
const to = computed(() => Math.min(props.page * props.limit, props.total))
</script>

<template>
  <div v-if="total > 0" class="pagination">
    <span class="pagination-info">
      Showing {{ from }}–{{ to }} of {{ total }}
    </span>
    <div class="pagination-buttons">
      <button
        class="btn btn-secondary btn-sm"
        :disabled="page <= 1"
        @click="emit('update:page', page - 1)"
      >
        <span class="mdi mdi-chevron-left" />
        Previous
      </button>
      <button
        class="btn btn-secondary btn-sm"
        :disabled="page >= totalPages"
        @click="emit('update:page', page + 1)"
      >
        Next
        <span class="mdi mdi-chevron-right" />
      </button>
    </div>
  </div>
</template>
