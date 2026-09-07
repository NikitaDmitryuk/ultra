'use strict';
(() => {
  const token = window.location.hash.slice(1);
  const status = document.getElementById('import-status');
  if (!/^[A-Za-z0-9_-]{43}$/.test(token) || window.location.protocol !== 'https:') return;
  // The token is a fragment, so the browser does not send it in the page request.
  // Keep it out of browser history and never send it to a third-party redirector.
  window.history.replaceState(null, '', window.location.pathname);
  const subscription = window.location.origin + '/sub/' + token;
  document.getElementById('launch-happ').href = 'happ://add/' + subscription;
  document.getElementById('import-subscription').value = subscription;
  document.getElementById('import-actions').hidden = false;
  status.textContent = 'Нажмите кнопку, чтобы добавить подписку в установленный Happ.';
  document.getElementById('copy-subscription').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(subscription);
      status.textContent = 'Ссылка скопирована. В Happ нажмите «+» и выберите импорт из буфера.';
    } catch (_) {
      document.getElementById('import-subscription').select();
      status.textContent = 'Ссылка выделена — скопируйте её вручную.';
    }
  });
})();
