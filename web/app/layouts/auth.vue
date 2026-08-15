<script setup lang="ts">
/**
 * Chrome for the sign-in screen: a brand panel on the left and the form column
 * on the right, collapsing to the form alone on narrow screens.
 *
 * Only the chrome lives here. The heading and the form stay in the page,
 * because the sign-in flow rewrites its own title when it moves to the
 * second-factor step — and because Vue's scoped CSS applies to slot content in
 * the *parent's* scope, so styling slotted markup from here would need
 * :slotted() and would couple the layout to the page's internals.
 */
import { useThemeStore } from '~/stores/theme'

const theme = useThemeStore()

/**
 * What Certio actually does, in the order someone evaluating it would care.
 * Decorative — the panel is hidden from assistive tech, and the form column
 * carries the real heading.
 */
const features = [
  { icon: 'certificate-outline', label: 'Roots, intermediates, or import your own CA' },
  { icon: 'dns-outline', label: 'Issuance with real SAN support' },
  { icon: 'autorenew', label: 'Auto-renewal, and deployment where it is used' },
  { icon: 'robot-outline', label: 'ACME for cert-manager, Traefik and certbot' },
  { icon: 'close-octagon-outline', label: 'Revocation, CRLs and an OCSP responder' },
  { icon: 'export-variant', label: 'Export in every format a server wants' },
]
</script>

<template>
  <div class="auth">
    <!-- Brand panel. Decorative and duplicated by the form column's own
         heading, so it is hidden from assistive tech. -->
    <aside class="auth-hero" aria-hidden="true">
      <div class="auth-hero-inner">
        <div class="auth-hero-brand">
          <AppLogo :size="34" />
          <span class="auth-hero-wordmark">Certio<span class="wm-dot">.</span></span>
        </div>

        <div class="auth-hero-body">
          <h2 class="auth-hero-title">Private PKI,<br>self-hosted.</h2>
          <p class="auth-hero-lead">
            Everything a certificate authority needs, without the pile of openssl
            commands it usually turns into. One engine behind the dashboard, the
            REST API and the CLI.
          </p>
          <ul class="auth-hero-features">
            <li v-for="feature in features" :key="feature.icon">
              <span class="mdi" :class="`mdi-${feature.icon}`" />
              {{ feature.label }}
            </li>
          </ul>
        </div>

        <p class="auth-hero-foot">Open-source · Self-hosted certificate management</p>
      </div>
    </aside>

    <main class="auth-main">
      <div class="auth-card">
        <div class="auth-brand">
          <AppLogo :size="34" />
          <span class="auth-brand-text">Certio<span class="auth-brand-dot">.</span></span>
        </div>

        <slot />
      </div>
    </main>

    <button
      class="theme-btn"
      :title="theme.isDark ? 'Light mode' : 'Dark mode'"
      :aria-label="theme.isDark ? 'Switch to light mode' : 'Switch to dark mode'"
      @click="theme.toggle()"
    >
      <span class="mdi" :class="theme.isDark ? 'mdi-white-balance-sunny' : 'mdi-weather-night'" />
    </button>
  </div>
</template>

<style scoped>
.auth {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 1.05fr 1fr;
  background: var(--bg-primary);
  position: relative;
}

/* ─── Brand panel ─── */
.auth-hero {
  position: relative;
  overflow: hidden;
  display: flex;
  color: #fff;
  /* The primary ramp above 500 is not redefined for dark mode, so this panel
     is the same purple in either theme — which is the point of a brand panel. */
  background:
    radial-gradient(120% 80% at 100% 0%, rgba(255, 255, 255, 0.16), transparent 55%),
    radial-gradient(90% 70% at 0% 100%, rgba(13, 20, 36, 0.5), transparent 60%),
    linear-gradient(150deg, var(--primary-600) 0%, var(--primary-800) 70%, #2a0f4d 100%);
}
/* Oversized initial as a watermark, echoing the lockup above it. */
.auth-hero::after {
  content: 'C';
  position: absolute;
  right: -10%;
  bottom: -30%;
  font-size: 32rem;
  font-weight: 800;
  line-height: 1;
  color: #fff;
  opacity: 0.05;
  pointer-events: none;
  user-select: none;
}
.auth-hero-inner {
  position: relative;
  z-index: 1;
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 460px;
  margin: auto;
  padding: 56px 52px;
}
.auth-hero-brand {
  display: flex;
  align-items: center;
  gap: 12px;
  align-self: flex-start;
  margin-bottom: auto;
}
.auth-hero-wordmark {
  font-size: 1.6rem;
  font-weight: 800;
  letter-spacing: -0.02em;
  color: #fff;
}
.auth-hero-wordmark .wm-dot { color: var(--primary-300); }

.auth-hero-body { margin: 48px 0; }
.auth-hero-title {
  /* Explicit, not inherited from .auth-hero. base.css colours every heading
     with --text-primary, and a direct selector beats inheritance — so without
     this the title takes the theme's body colour and turns near-black on the
     purple panel in light mode. The panel is the same purple in either theme,
     so its text is white in either theme too. */
  color: #fff;
  font-size: clamp(1.9rem, 2.6vw, 2.6rem);
  font-weight: 800;
  line-height: 1.1;
  letter-spacing: -0.02em;
  margin: 0 0 16px;
}
.auth-hero-lead {
  font-size: 15px;
  line-height: 1.6;
  color: rgba(255, 255, 255, 0.82);
  max-width: 42ch;
  margin: 0 0 28px;
}
.auth-hero-features {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.auth-hero-features li {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 14px;
  color: rgba(255, 255, 255, 0.92);
}
.auth-hero-features .mdi {
  font-size: 20px;
  flex-shrink: 0;
  width: 34px;
  height: 34px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius);
  background: rgba(255, 255, 255, 0.12);
}
.auth-hero-foot {
  margin: 0;
  font-size: 12.5px;
  color: rgba(255, 255, 255, 0.6);
}

/* ─── Form column ─── */
.auth-main {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px 24px;
}
.auth-card {
  width: 100%;
  max-width: 380px;
}
.auth-brand {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  margin-bottom: 24px;
}
.auth-brand-text {
  font-size: 30px;
  font-weight: 800;
  letter-spacing: -0.03em;
  line-height: 1;
  color: var(--text-primary);
}
.auth-brand-dot { color: var(--primary-500); }

.theme-btn {
  position: fixed;
  top: 20px;
  right: 20px;
  background: var(--bg-primary);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius);
  padding: 8px 10px;
  cursor: pointer;
  color: var(--text-tertiary);
  display: flex;
  align-items: center;
  font-size: 17px;
  line-height: 1;
  transition: all var(--transition);
  box-shadow: var(--shadow-sm);
}
.theme-btn:hover { color: var(--text-primary); border-color: var(--border-input); }

/* ─── Responsive: collapse to a single centred form ─── */
@media (max-width: 900px) {
  .auth { grid-template-columns: 1fr; }
  .auth-hero { display: none; }
}
</style>
