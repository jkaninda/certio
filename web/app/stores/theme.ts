import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'

export type ThemeMode = 'light' | 'dark' | 'system'

const STORAGE_KEY = 'certio_theme'

export const useThemeStore = defineStore('theme', () => {
  const mode = ref<ThemeMode>('system')
  const systemDark = ref(false)

  const isDark = computed(() => (mode.value === 'system' ? systemDark.value : mode.value === 'dark'))

  function apply() {
    if (!import.meta.client) return
    document.documentElement.setAttribute('data-theme', isDark.value ? 'dark' : 'light')
  }

  /**
   * init reads the stored preference and starts tracking the OS setting. The
   * inline script in nuxt.config already applied the right theme before first
   * paint; this only takes over the reactive half.
   */
  function init() {
    if (!import.meta.client) return

    const stored = localStorage.getItem(STORAGE_KEY) as ThemeMode | null
    if (stored === 'light' || stored === 'dark' || stored === 'system') {
      mode.value = stored
    }

    const query = window.matchMedia('(prefers-color-scheme: dark)')
    systemDark.value = query.matches
    query.addEventListener('change', (event) => {
      systemDark.value = event.matches
    })

    watch([mode, systemDark], apply, { immediate: true })
    watch(mode, (value) => localStorage.setItem(STORAGE_KEY, value))
  }

  function setMode(value: ThemeMode) {
    mode.value = value
  }

  function toggle() {
    mode.value = isDark.value ? 'light' : 'dark'
  }

  return { mode, isDark, init, setMode, toggle }
})
