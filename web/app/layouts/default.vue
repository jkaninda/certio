<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useAuthStore } from '~/stores/auth'
import { useThemeStore } from '~/stores/theme'
import { useCatalogStore } from '~/stores/catalog'
import { useToast } from '~/composables/useToast'

const route = useRoute()
const auth = useAuthStore()
const theme = useThemeStore()
const catalog = useCatalogStore()

const sidebarCollapsed = ref(false)
const mobileOpen = ref(false)
const userMenuOpen = ref(false)
const caSwitcherOpen = ref(false)
const themeModes = ['light', 'dark', 'system'] as const

interface NavItem {
  name: string
  path: string
  icon: string
  /** Extra path prefixes that should keep this item highlighted. */
  matchPaths?: string[]
  adminOnly?: boolean
  external?: boolean
}

interface NavSection {
  id: string
  title: string
  items: NavItem[]
}

const navSections: NavSection[] = [
  {
    id: 'overview',
    title: 'Overview',
    items: [{ name: 'Dashboard', path: '/', icon: 'view-dashboard-outline' }],
  },
  {
    id: 'pki',
    title: 'Public key infrastructure',
    items: [
      { name: 'Authorities', path: '/authorities', icon: 'certificate-outline' },
      { name: 'Certificates', path: '/certificates', icon: 'file-certificate-outline' },
      { name: 'Issue', path: '/certificates/new', icon: 'plus-circle-outline' },
      { name: 'Inspect', path: '/inspect', icon: 'magnify-scan' },
    ],
  },
  {
    id: 'operations',
    title: 'Operations',
    items: [
      { name: 'Audit log', path: '/audit', icon: 'text-box-search-outline', adminOnly: true },
      { name: 'Jobs', path: '/jobs', icon: 'timer-cog-outline', adminOnly: true },
    ],
  },
  {
    id: 'settings',
    title: 'Settings',
    items: [
      { name: 'General', path: '/settings', icon: 'cog-outline', adminOnly: true },
      { name: 'Security', path: '/settings/security', icon: 'shield-key-outline' },
      { name: 'Users', path: '/settings/users', icon: 'account-group-outline', adminOnly: true },
      { name: 'API tokens', path: '/settings/tokens', icon: 'key-variant' },
      { name: 'Notifications', path: '/settings/notifications', icon: 'bell-outline', adminOnly: true },
      { name: 'API docs', path: '/docs', icon: 'api', external: true },
      { name: 'About', path: '/about', icon: 'information-outline' },
    ],
  },
]

const visibleSections = computed(() =>
  navSections
    .map((section) => ({
      ...section,
      items: section.items.filter((item) => !item.adminOnly || auth.isAdmin),
    }))
    .filter((section) => section.items.length > 0),
)

function isActive(item: NavItem): boolean {
  if (item.path === '/') return route.path === '/'
  // "Issue" and "Certificates" share a prefix, so the more specific one wins.
  if (item.path === '/certificates') {
    return route.path.startsWith('/certificates') && route.path !== '/certificates/new'
  }
  // Same for "General": every settings sub-page has an entry of its own.
  if (item.path === '/settings') return route.path === '/settings'
  if (route.path === item.path || route.path.startsWith(`${item.path}/`)) return true
  return item.matchPaths?.some((p) => route.path.startsWith(p)) ?? false
}

function toggleSidebar() {
  sidebarCollapsed.value = !sidebarCollapsed.value
  localStorage.setItem('certio_sidebar_collapsed', String(sidebarCollapsed.value))
}

function selectAuthority(id: string | null) {
  catalog.setActiveAuthority(id)
  caSwitcherOpen.value = false
  if (route.path.startsWith('/certificates') && route.path !== '/certificates/new') {
    navigateTo(id ? `/certificates?ca=${id}` : '/certificates')
  }
}

function closeMenus(event: MouseEvent) {
  const target = event.target as Element | null
  if (userMenuOpen.value && !target?.closest?.('.user-menu')) userMenuOpen.value = false
  if (caSwitcherOpen.value && !target?.closest?.('.ca-switcher')) caSwitcherOpen.value = false
}

onMounted(async () => {
  sidebarCollapsed.value = localStorage.getItem('certio_sidebar_collapsed') === 'true'
  document.addEventListener('click', closeMenus)
  noticeRecoveryCodeLogin()
  await catalog.load()
})

/**
 * noticeRecoveryCodeLogin surfaces the warning the login page could not show:
 * it navigates away the moment the session exists, so the message is handed
 * over here instead.
 */
function noticeRecoveryCodeLogin() {
  const remaining = sessionStorage.getItem('certio_recovery_notice')
  if (remaining === null) return
  sessionStorage.removeItem('certio_recovery_notice')

  const toast = useToast()
  toast.warning(
    `You signed in with a recovery code — it has now been used up, and ${remaining} remain. ` +
    'Set up your authenticator again from Settings → Security.',
  )
}

onBeforeUnmount(() => document.removeEventListener('click', closeMenus))

const activeAuthorityLabel = computed(() => {
  const active = catalog.activeAuthority
  return active ? active.name : 'All authorities'
})
</script>

<template>
  <div class="layout" :class="{ 'sidebar-collapsed': sidebarCollapsed }">
    <!-- Backdrop for the mobile drawer -->
    <div v-if="mobileOpen" class="mobile-backdrop" @click="mobileOpen = false" />

    <aside class="sidebar" :class="{ 'sidebar-mobile-open': mobileOpen }">
      <div class="sidebar-header">
        <NuxtLink to="/" class="sidebar-brand">
          <AppLogo class="sidebar-logo" :size="34" />
          <span class="sidebar-brand-text">Certio<span class="sidebar-brand-dot">.</span></span>
        </NuxtLink>
        <button
          class="sidebar-collapse-btn"
          :title="sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'"
          :aria-label="sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'"
          @click="toggleSidebar"
        >
          <span class="mdi" :class="sidebarCollapsed ? 'mdi-chevron-right' : 'mdi-chevron-left'" />
        </button>
      </div>

      <!-- Active CA switcher. Certio has no workspaces, so this slot holds the
           scope that actually matters here: which authority you are working in. -->
      <div class="ca-switcher">
        <button class="ca-switcher-toggle" @click.stop="caSwitcherOpen = !caSwitcherOpen">
          <span class="ca-switcher-current">
            <span class="ca-avatar">{{ activeAuthorityLabel.charAt(0).toUpperCase() }}</span>
            <span v-if="!sidebarCollapsed" class="ca-switcher-name">{{ activeAuthorityLabel }}</span>
          </span>
          <span v-if="!sidebarCollapsed" class="mdi mdi-unfold-more-horizontal" />
        </button>

        <div v-if="caSwitcherOpen" class="ca-switcher-dropdown" @click.stop>
          <button
            class="ca-switcher-option"
            :class="{ active: !catalog.activeAuthorityId }"
            @click="selectAuthority(null)"
          >
            <span class="ca-avatar-sm">∗</span>
            <span>All authorities</span>
          </button>
          <div v-if="catalog.authorities.length" class="dropdown-divider" />
          <button
            v-for="ca in catalog.authorities"
            :key="ca.id"
            class="ca-switcher-option"
            :class="{ active: catalog.activeAuthorityId === ca.id }"
            @click="selectAuthority(ca.id)"
          >
            <span class="ca-avatar-sm">{{ ca.name.charAt(0).toUpperCase() }}</span>
            <span class="truncate">{{ ca.name }}</span>
            <span class="ca-role-badge">{{ ca.type }}</span>
          </button>
          <div class="dropdown-divider" />
          <NuxtLink to="/authorities/new" class="ca-switcher-option" @click="caSwitcherOpen = false">
            <span class="ca-avatar-sm">+</span>
            <span>New authority</span>
          </NuxtLink>
        </div>
      </div>

      <nav class="sidebar-nav">
        <div v-for="section in visibleSections" :key="section.id" class="nav-section">
          <p v-if="!sidebarCollapsed" class="nav-section-title">{{ section.title }}</p>
          <a
            v-for="item in section.items"
            :key="item.path"
            v-bind="item.external
              ? { href: item.path, target: '_blank', rel: 'noopener noreferrer' }
              : {}"
            class="nav-item"
            :class="{ active: !item.external && isActive(item) }"
            :title="sidebarCollapsed ? item.name : undefined"
            @click="!item.external && (mobileOpen = false, navigateTo(item.path))"
          >
            <span class="nav-icon mdi" :class="`mdi-${item.icon}`" />
            <span v-if="!sidebarCollapsed" class="nav-label">{{ item.name }}</span>
            <span v-if="!sidebarCollapsed && item.external" class="mdi mdi-open-in-new nav-external" />
          </a>
        </div>
      </nav>

      <div v-if="!sidebarCollapsed" class="sidebar-footer">
        <span class="sidebar-version">v{{ catalog.meta?.version ?? '—' }}</span>
      </div>
    </aside>

    <div class="main-wrapper">
      <header class="topbar">
        <div class="topbar-left">
          <button class="mobile-menu-btn" aria-label="Open navigation" @click.stop="mobileOpen = true">
            <span class="mdi mdi-menu" />
          </button>
        </div>

        <div class="topbar-right">
          <NuxtLink to="/certificates/new" class="btn btn-primary btn-sm topbar-cta">
            <span class="mdi mdi-plus" />
            <span class="topbar-cta-label">Issue certificate</span>
          </NuxtLink>

          <div class="user-menu" @click.stop="userMenuOpen = !userMenuOpen">
            <span class="avatar avatar-sm">{{ (auth.user?.name || auth.user?.email || '?').charAt(0) }}</span>
            <div class="user-menu-info">
              <div class="user-name">{{ auth.user?.name || 'User' }}</div>
              <div class="user-email">{{ auth.user?.email }}</div>
            </div>
            <span class="mdi mdi-chevron-down" />

            <div v-if="userMenuOpen" class="dropdown-menu user-dropdown" @click.stop>
              <div class="user-dropdown-header">
                <span class="avatar">{{ (auth.user?.name || auth.user?.email || '?').charAt(0) }}</span>
                <div class="cell-text">
                  <span class="cell-title">{{ auth.user?.name }}</span>
                  <span class="cell-sub">{{ auth.user?.email }}</span>
                </div>
              </div>
              <div class="user-dropdown-role">
                <span class="badge badge-info">{{ auth.user?.role }}</span>
              </div>
              <div class="dropdown-divider" />

              <div class="theme-row">
                <span class="theme-row-label">
                  <span class="mdi mdi-theme-light-dark" />
                  Theme
                </span>
                <div class="theme-switcher">
                  <button
                    v-for="m in themeModes"
                    :key="m"
                    class="theme-btn"
                    :class="{ active: theme.mode === m }"
                    :title="m"
                    :aria-label="`Use the ${m} theme`"
                    @click.stop="theme.setMode(m)"
                  >
                    <span
                      class="mdi"
                      :class="m === 'light' ? 'mdi-white-balance-sunny'
                        : m === 'dark' ? 'mdi-weather-night' : 'mdi-monitor'"
                    />
                  </button>
                </div>
              </div>

              <div class="dropdown-divider" />
              <button class="dropdown-item dropdown-item-danger" @click="auth.logout()">
                <span class="mdi mdi-logout" />
                Sign out
              </button>
            </div>
          </div>
        </div>
      </header>

      <main class="main-content">
        <slot />
      </main>
    </div>
  </div>
</template>

<style scoped>
.layout {
  display: flex;
  min-height: 100vh;
  background: var(--bg-secondary);
}

/* ─── Sidebar ─── */
.sidebar {
  position: fixed;
  top: 0;
  left: 0;
  bottom: 0;
  width: var(--sidebar-width);
  background: var(--bg-sidebar);
  display: flex;
  flex-direction: column;
  z-index: 40;
  transition: width var(--transition-slow), transform var(--transition-slow);
}
.sidebar-collapsed .sidebar { width: var(--sidebar-width-collapsed); }

.sidebar-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 16px 14px 12px;
  flex-shrink: 0;
  position: relative;
}
.sidebar-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  color: #fff;
  min-width: 0;
}
.sidebar-brand:hover { color: #fff; }
/* No background or radius of its own: the mark carries its own tile and
   corners, and a container behind it would only show as a halo. */
.sidebar-logo { flex-shrink: 0; }
.sidebar-brand-text {
  font-size: 15px;
  font-weight: 700;
  white-space: nowrap;
  overflow: hidden;
  transition: opacity var(--transition-slow);
}
.sidebar-brand-dot { color: var(--primary-400); }
.sidebar-collapsed .sidebar-brand-text { opacity: 0; width: 0; }

.sidebar-collapse-btn {
  position: absolute;
  top: 20px;
  right: 10px;
  background: none;
  border: none;
  color: var(--sidebar-text);
  cursor: pointer;
  padding: 3px;
  border-radius: var(--radius-sm);
  display: flex;
  font-size: 18px;
  transition: color var(--transition), background var(--transition);
}
.sidebar-collapse-btn:hover { color: #fff; background: var(--sidebar-hover); }
.sidebar-collapsed .sidebar-collapse-btn {
  right: -13px;
  background: var(--bg-sidebar);
  border: 1px solid var(--sidebar-border);
  z-index: 41;
}

/* ─── CA switcher ─── */
.ca-switcher { padding: 0 8px 8px; position: relative; }
.ca-switcher-toggle {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 8px 10px;
  border-radius: var(--radius);
  cursor: pointer;
  color: var(--sidebar-text);
  background: transparent;
  border: 1px solid var(--sidebar-border);
  font-family: inherit;
  font-size: 13px;
  transition: all var(--transition);
}
.ca-switcher-toggle:hover { background: var(--sidebar-hover); color: var(--sidebar-text-active); }
.ca-switcher-current { display: flex; align-items: center; gap: 8px; overflow: hidden; }
.ca-switcher-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.ca-avatar {
  width: 24px; height: 24px;
  border-radius: 6px;
  background: var(--primary-600);
  color: #fff;
  display: flex; align-items: center; justify-content: center;
  font-size: 12px; font-weight: 600;
  flex-shrink: 0;
}
.ca-avatar-sm {
  width: 20px; height: 20px;
  border-radius: 5px;
  background: var(--primary-100);
  color: var(--primary-700);
  display: flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 600;
  flex-shrink: 0;
}
[data-theme="dark"] .ca-avatar-sm { background: var(--primary-900); color: var(--primary-200); }

.ca-switcher-dropdown {
  position: absolute;
  left: 8px;
  right: 8px;
  top: calc(100% - 2px);
  background: var(--bg-primary);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  box-shadow: var(--shadow-lg);
  padding: 6px;
  z-index: 60;
  max-height: 60vh;
  overflow-y: auto;
}
.ca-switcher-option {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 7px 8px;
  border: none;
  background: transparent;
  border-radius: var(--radius-sm);
  font-size: 13px;
  color: var(--text-secondary);
  cursor: pointer;
  text-align: left;
  font-family: inherit;
}
.ca-switcher-option:hover { background: var(--bg-hover); color: var(--text-primary); }
.ca-switcher-option.active { background: var(--bg-active); color: var(--primary-700); font-weight: 500; }
[data-theme="dark"] .ca-switcher-option.active { color: var(--primary-200); }
.ca-role-badge {
  margin-left: auto;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
  flex-shrink: 0;
}

/* ─── Navigation ─── */
.sidebar-nav {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 8px;
}
.nav-section + .nav-section { margin-top: 18px; }
.nav-section-title {
  font-size: 10.5px;
  font-weight: 600;
  color: var(--sidebar-text);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 4px 12px 6px;
  white-space: nowrap;
  opacity: 0.55;
}

.nav-item {
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 7px 12px;
  border-radius: var(--radius);
  color: var(--sidebar-text);
  font-size: 13px;
  cursor: pointer;
  transition: background var(--transition), color var(--transition);
  white-space: nowrap;
  overflow: hidden;
}
.nav-item:hover { background: var(--sidebar-hover); color: var(--sidebar-text-active); }
.nav-item.active {
  background: var(--sidebar-hover);
  color: var(--sidebar-text-active);
  font-weight: 500;
}
.nav-item.active::before {
  content: '';
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%);
  width: 3px;
  height: 20px;
  background: var(--primary-500);
  border-radius: 0 3px 3px 0;
}
.nav-icon { flex-shrink: 0; font-size: 17px; opacity: 0.75; }
.nav-item.active .nav-icon { opacity: 1; }
.nav-external { margin-left: auto; font-size: 12px; opacity: 0.5; }
.sidebar-collapsed .nav-item { justify-content: center; padding: 9px; }

.sidebar-footer {
  padding: 10px 16px 14px;
  border-top: 1px solid var(--sidebar-border);
}
.sidebar-version { font-size: 11px; color: var(--sidebar-text); opacity: 0.6; }

/* ─── Main ─── */
.main-wrapper {
  flex: 1;
  margin-left: var(--sidebar-width);
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  min-width: 0;
  transition: margin-left var(--transition-slow);
}
.sidebar-collapsed .main-wrapper { margin-left: var(--sidebar-width-collapsed); }

.topbar {
  position: sticky;
  top: 0;
  z-index: 30;
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: var(--topbar-height);
  padding: 0 24px;
  background: var(--bg-primary);
  border-bottom: 1px solid var(--border-primary);
  transition: background var(--transition-slow), border-color var(--transition-slow);
}
.topbar-left { display: flex; align-items: center; }
.topbar-right { display: flex; align-items: center; gap: 12px; margin-left: auto; }

.mobile-menu-btn {
  display: none;
  align-items: center;
  justify-content: center;
  background: none;
  border: none;
  color: var(--text-tertiary);
  cursor: pointer;
  padding: 6px;
  font-size: 22px;
  border-radius: var(--radius-sm);
}
.mobile-menu-btn:hover { color: var(--text-primary); background: var(--bg-hover); }

.user-menu {
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 4px 8px 4px 4px;
  border-radius: var(--radius);
  cursor: pointer;
  transition: background var(--transition);
  color: var(--text-tertiary);
}
.user-menu:hover { background: var(--bg-hover); }
.user-menu-info { display: flex; flex-direction: column; line-height: 1.25; min-width: 0; }
.user-name { font-size: 13px; font-weight: 550; color: var(--text-primary); }
.user-email { font-size: 11.5px; color: var(--text-muted); }

.user-dropdown { min-width: 260px; }
.user-dropdown-header { display: flex; align-items: center; gap: 10px; padding: 10px; }
.user-dropdown-role { padding: 0 10px 8px; }

.theme-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 10px;
  gap: 12px;
}
.theme-row-label {
  display: flex; align-items: center; gap: 8px;
  font-size: 13.5px; color: var(--text-secondary);
}
.theme-row-label .mdi { font-size: 16px; color: var(--text-muted); }
.theme-switcher {
  display: flex;
  gap: 2px;
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
  padding: 2px;
}
.theme-btn {
  display: flex; align-items: center; justify-content: center;
  width: 26px; height: 24px;
  border: none;
  background: transparent;
  border-radius: 4px;
  color: var(--text-tertiary);
  cursor: pointer;
  font-size: 14px;
  transition: all var(--transition);
}
.theme-btn:hover { color: var(--text-primary); }
.theme-btn.active { background: var(--bg-primary); color: var(--primary-600); box-shadow: var(--shadow-sm); }

.main-content {
  flex: 1;
  padding: 28px;
  min-width: 0;
}

.mobile-backdrop {
  display: none;
  position: fixed;
  inset: 0;
  background: var(--overlay);
  z-index: 39;
}

@media (max-width: 900px) {
  .sidebar { transform: translateX(-100%); width: var(--sidebar-width); }
  .sidebar-mobile-open { transform: translateX(0); }
  .sidebar-collapsed .sidebar { width: var(--sidebar-width); }
  .main-wrapper, .sidebar-collapsed .main-wrapper { margin-left: 0; }
  .mobile-menu-btn { display: flex; }
  .mobile-backdrop { display: block; }
  .sidebar-collapse-btn { display: none; }
  .main-content { padding: 18px; }
  .user-menu-info { display: none; }
  .topbar-cta-label { display: none; }
}
</style>
