'use strict';
(() => {
  const fragment = window.location.hash.slice(1);
  // Remove the sensitive fragment even when it is malformed. No network request
  // or persistent browser storage is needed to hand off to the installed client.
  window.history.replaceState(null, '', window.location.pathname);
  if (window.location.protocol !== 'https:') return;
  try {
    const link = new URL(decodeURIComponent(fragment));
    // Only subscription-import actions are accepted, never arbitrary browser,
    // intent, file or script URLs supplied through the fragment.
    if (!/^[a-z][a-z0-9+.-]*:$/.test(link.protocol) ||
        ['http:', 'https:', 'javascript:', 'data:', 'file:', 'blob:', 'intent:'].includes(link.protocol) ||
        !['add', 'add-subscription'].includes(link.host) || link.username || link.password ||
        (link.pathname && link.pathname !== '/') || link.hash) return;
    const subscription = new URL(link.searchParams.get('url'));
    if (subscription.origin !== window.location.origin ||
        !/^\/sub\/[A-Za-z0-9_-]{43}$/.test(subscription.pathname) ||
        subscription.search !== '?format=olcrtc' || subscription.hash ||
        subscription.username || subscription.password) return;
    document.getElementById('launch-client').href = link.href;
    document.getElementById('import-actions').hidden = false;
    document.getElementById('import-status').textContent = 'Нажмите кнопку ниже, чтобы открыть приложение.';
  } catch (_) {
    // Invalid links leave the page inert and do not echo private values.
  }
})();
