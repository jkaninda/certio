// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Certio - Self-signed PKI and TLS certificate management
// Copyright (C) 2026 Jonas Kaninda
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import type { Authority, Meta } from '~/types/api'

/**
 * The catalog holds reference data the whole dashboard depends on: the list of
 * authorities for the switcher and every selector, and the backend's own
 * declaration of the profiles, algorithms and export formats it supports.
 * Fetching it once here keeps the forms from hard-coding a list the server owns.
 */
export const useCatalogStore = defineStore('catalog', () => {
  const authorities = ref<Authority[]>([])
  const meta = ref<Meta | null>(null)
  const loading = ref(false)
  const activeAuthorityId = ref<string | null>(null)

  const activeAuthority = computed(
    () => authorities.value.find((a) => a.id === activeAuthorityId.value) ?? null,
  )

  /** issuableAuthorities excludes anything that can no longer sign. */
  const issuableAuthorities = computed(() =>
    authorities.value.filter((a) => a.status !== 'expired' && a.status !== 'revoked'),
  )

  async function load(force = false) {
    if (loading.value) return
    if (!force && meta.value && authorities.value.length > 0) return

    loading.value = true
    const api = useApi()
    try {
      const [caPage, metaPayload] = await Promise.all([
        api.get<{ items: Authority[] }>('/authorities', { limit: 200 }),
        api.get<Meta>('/meta'),
      ])
      authorities.value = caPage.items ?? []
      meta.value = metaPayload
    } catch {
      // The layout must still render for a user whose token has just expired;
      // the API layer already redirected them to the login page.
    } finally {
      loading.value = false
    }
  }

  async function refreshAuthorities() {
    const api = useApi()
    const page = await api.get<{ items: Authority[] }>('/authorities', { limit: 200 })
    authorities.value = page.items ?? []
  }

  function setActiveAuthority(id: string | null) {
    activeAuthorityId.value = id
    if (import.meta.client) {
      if (id) localStorage.setItem('certio_active_ca', id)
      else localStorage.removeItem('certio_active_ca')
    }
  }

  function authorityName(id: string): string {
    return authorities.value.find((a) => a.id === id)?.name ?? '—'
  }

  return {
    authorities, meta, loading, activeAuthorityId,
    activeAuthority, issuableAuthorities,
    load, refreshAuthorities, setActiveAuthority, authorityName,
  }
})
