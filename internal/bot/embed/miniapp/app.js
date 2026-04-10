'use strict';

const tg = window.Telegram.WebApp;
tg.ready();
tg.expand();

// ── State ────────────────────────────────────────────────────────────────────
let currentUserUUID = null;
let currentVlessURI = null;
let usersCache = [];
let monthlyChart = null;
let usersChart = null;

// ── Init ─────────────────────────────────────────────────────────────────────
(async function init() {
  try {
    await checkAuth();
    await loadStats();
    await loadUsers();
    loadSettingsMe();
  } catch (e) {
    showError(e.message || 'Ошибка инициализации');
  }
})();

async function checkAuth() {
  const res = await api('GET', '/api/me');
  if (!res.is_admin) {
    showError('Вы не являетесь администратором.');
    throw new Error('not admin');
  }
}

// ── Navigation ───────────────────────────────────────────────────────────────
function showScreen(name) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const s = document.getElementById('screen-' + name);
  if (s) s.classList.add('active');
  const navBtn = document.querySelector(`.nav-btn[data-screen="${name}"]`);
  if (navBtn) navBtn.classList.add('active');
}

function switchTab(name, btn) {
  showScreen(name);
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  if (name === 'stats') loadStats();
  if (name === 'users') loadUsers();
}

function showAddUser() {
  showScreen('add-user');
  document.getElementById('new-user-name').value = '';
  document.getElementById('new-user-name').focus();
}

// ── Stats ────────────────────────────────────────────────────────────────────
async function loadStats() {
  document.getElementById('stats-loader').style.display = 'block';
  try {
    const [data, history] = await Promise.all([
      api('GET', '/api/stats'),
      api('GET', '/api/stats/history').catch(() => []),
    ]);
    document.getElementById('stat-users').textContent = data.total_users;
    document.getElementById('stat-traffic').textContent = formatBytes(data.total_bytes_month);
    if (data.stats_month) {
      const d = new Date(data.stats_month.year, data.stats_month.month - 1);
      document.getElementById('stats-month').textContent =
        d.toLocaleDateString('ru-RU', { month: 'long', year: 'numeric' });
    }
    // Use cached users for per-user chart; fetch only if cache is empty.
    const users = usersCache.length > 0
      ? usersCache
      : await api('GET', '/api/users').catch(() => []);
    renderCharts(history || [], users);
  } catch (e) {
    console.error('loadStats', e);
  } finally {
    document.getElementById('stats-loader').style.display = 'none';
  }
}

function renderCharts(history, users) {
  const MONTH_RU = ['Янв','Фев','Мар','Апр','Май','Июн','Июл','Авг','Сен','Окт','Ноя','Дек'];
  const BAR_COLOR = 'rgba(82,136,193,0.8)';
  const BAR_HOVER = 'rgba(82,136,193,1)';
  const TICK_COLOR = getComputedStyle(document.documentElement)
    .getPropertyValue('--tg-hint').trim() || '#888';
  const GRID_COLOR = 'rgba(136,136,136,0.15)';

  // Monthly history chart
  const monthCtx = document.getElementById('chart-monthly');
  if (monthlyChart) { monthlyChart.destroy(); monthlyChart = null; }
  if (history && history.length > 0) {
    document.getElementById('chart-history-card').style.display = '';
    monthlyChart = new Chart(monthCtx, {
      type: 'bar',
      data: {
        labels: history.map(p => `${MONTH_RU[(p.Month || 1) - 1]} ${p.Year}`),
        datasets: [{
          data: history.map(p => +((p.TotalBytes || 0) / 1073741824).toFixed(2)),
          backgroundColor: BAR_COLOR,
          hoverBackgroundColor: BAR_HOVER,
          borderRadius: 4,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: TICK_COLOR, font: { size: 11 } }, grid: { display: false } },
          y: { ticks: { color: TICK_COLOR, font: { size: 11 }, callback: v => v + ' ГБ' },
               grid: { color: GRID_COLOR } },
        },
      },
    });
  } else {
    document.getElementById('chart-history-card').style.display = 'none';
  }

  // Per-user chart (current month, top 8 by traffic)
  const usersCtx = document.getElementById('chart-users');
  if (usersChart) { usersChart.destroy(); usersChart = null; }
  const activeUsers = (users || [])
    .filter(u => (u.total_bytes || 0) > 0)
    .sort((a, b) => (b.total_bytes || 0) - (a.total_bytes || 0))
    .slice(0, 8);
  if (activeUsers.length > 0) {
    document.getElementById('chart-users-card').style.display = '';
    usersChart = new Chart(usersCtx, {
      type: 'bar',
      data: {
        labels: activeUsers.map(u => u.name || u.uuid.slice(0, 8)),
        datasets: [{
          data: activeUsers.map(u => +((u.total_bytes || 0) / 1073741824).toFixed(2)),
          backgroundColor: BAR_COLOR,
          hoverBackgroundColor: BAR_HOVER,
          borderRadius: 4,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: TICK_COLOR, font: { size: 11 }, callback: v => v + ' ГБ' },
               grid: { color: GRID_COLOR } },
          y: { ticks: { color: TICK_COLOR, font: { size: 11 } }, grid: { display: false } },
        },
      },
    });
  } else {
    document.getElementById('chart-users-card').style.display = 'none';
  }
}

// ── Users ────────────────────────────────────────────────────────────────────
async function loadUsers() {
  const loader = document.getElementById('users-loader');
  const list = document.getElementById('users-list');
  loader.style.display = 'block';
  list.innerHTML = '';
  try {
    usersCache = await api('GET', '/api/users');
    renderUsers(usersCache);
  } catch (e) {
    list.innerHTML = `<div class="empty">Ошибка загрузки: ${e.message}</div>`;
  } finally {
    loader.style.display = 'none';
  }
}

function renderUsers(users) {
  const list = document.getElementById('users-list');
  list.innerHTML = '';
  if (!users || users.length === 0) {
    list.innerHTML = '<div class="empty">Нет пользователей.<br>Нажмите + Добавить.</div>';
    return;
  }
  users.forEach(u => {
    const item = document.createElement('div');
    item.className = 'user-item';
    item.onclick = () => openUserDetail(u);
    const initial = (u.name || '?')[0].toUpperCase();
    const traffic = formatBytes(u.total_bytes || 0);
    const badge = lastSeenBadge(u.last_seen_at);
    item.innerHTML = `
      <div class="user-avatar">${initial}</div>
      <div class="user-info">
        <div class="user-name">${esc(u.name)}</div>
        <div class="user-traffic">${traffic} этот месяц</div>
        <div>${badge}</div>
      </div>
      <svg class="user-chevron" width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
        <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/>
      </svg>`;
    list.appendChild(item);
  });
}

function lastSeenBadge(isoStr) {
  if (!isoStr) return '<span class="seen-never">не активен</span>';
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return '<span class="seen-never">не активен</span>';
  const diffMin = Math.floor((Date.now() - d.getTime()) / 60000);
  if (diffMin < 5) return '<span class="seen-online">● онлайн</span>';
  if (diffMin < 60) return `<span class="seen-recent">${diffMin} мин назад</span>`;
  const hm = d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  if (new Date().toDateString() === d.toDateString()) {
    return `<span class="seen-hint">сегодня ${hm}</span>`;
  }
  const MONTHS = ['янв','фев','мар','апр','май','июн','июл','авг','сен','окт','ноя','дек'];
  return `<span class="seen-hint">${d.getDate()} ${MONTHS[d.getMonth()]} ${hm}</span>`;
}

async function createUser() {
  const name = document.getElementById('new-user-name').value.trim();
  if (!name) { tg.showAlert('Введите имя.'); return; }
  try {
    await api('POST', '/api/users', { name });
    showScreen('users');
    await loadUsers();
    tg.showAlert(`Пользователь "${name}" создан.`);
  } catch (e) {
    tg.showAlert('Ошибка: ' + e.message);
  }
}

// ── User detail ──────────────────────────────────────────────────────────────
async function openUserDetail(u) {
  currentUserUUID = u.uuid;
  currentVlessURI = null;
  document.getElementById('detail-name').textContent = u.name;
  document.getElementById('detail-traffic').textContent = formatBytes(u.total_bytes || 0) + ' этот месяц';
  document.getElementById('detail-vless-uri').textContent = 'Загрузка…';
  document.getElementById('qr-container').innerHTML = '';
  showScreen('user-detail');

  try {
    const cfg = await api('GET', `/api/users/${u.uuid}/config`);
    currentVlessURI = cfg.vless_uri || '';
    document.getElementById('detail-vless-uri').textContent = currentVlessURI;
    if (currentVlessURI && window.QRCode) {
      QRCode.toCanvas(currentVlessURI, { width: 220, margin: 2, color: { dark: '#000000', light: '#ffffff' } },
        (err, canvas) => {
          if (!err) document.getElementById('qr-container').appendChild(canvas);
        });
    }
  } catch (e) {
    document.getElementById('detail-vless-uri').textContent = 'Ошибка загрузки конфигурации.';
  }
}

function copyVlessURI() {
  if (!currentVlessURI) return;
  navigator.clipboard.writeText(currentVlessURI).then(
    () => tg.showAlert('VLESS URI скопирован.'),
    () => tg.showAlert('Не удалось скопировать.'),
  );
}

async function deleteCurrentUser() {
  if (!currentUserUUID) return;
  const user = usersCache.find(u => u.uuid === currentUserUUID);
  const name = user ? user.name : currentUserUUID;
  tg.showConfirm(`Удалить пользователя "${name}"?`, async (confirmed) => {
    if (!confirmed) return;
    try {
      await api('DELETE', `/api/users/${currentUserUUID}`);
      showScreen('users');
      await loadUsers();
    } catch (e) {
      tg.showAlert('Ошибка удаления: ' + e.message);
    }
  });
}

// ── Settings ─────────────────────────────────────────────────────────────────
async function loadSettingsMe() {
  try {
    const me = await api('GET', '/api/me');
    document.getElementById('settings-me').textContent = me.name + (me.username ? ` (@${me.username})` : '');
  } catch (_) {}
}

async function generateInvite() {
  try {
    const res = await api('POST', '/api/admin/invite');
    const box = document.getElementById('invite-token');
    box.textContent = `/start ${res.token}`;
    document.getElementById('invite-result').style.display = 'block';
  } catch (e) {
    tg.showAlert('Ошибка: ' + e.message);
  }
}

function copyInviteToken() {
  const text = document.getElementById('invite-token').textContent;
  navigator.clipboard.writeText(text).then(
    () => tg.showAlert('Токен скопирован.'),
    () => tg.showAlert('Не удалось скопировать.'),
  );
}

// ── API helper ───────────────────────────────────────────────────────────────
async function api(method, path, body) {
  const opts = {
    method,
    headers: {
      'X-Telegram-Init-Data': tg.initData,
    },
  };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 204) return null;
  const text = await res.text();
  if (!res.ok) throw new Error(text || res.statusText);
  if (!text) return null;
  return JSON.parse(text);
}

// ── Utils ────────────────────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return (i === 0 ? value.toFixed(0) : value.toFixed(1)) + ' ' + units[i];
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function showError(msg) {
  document.body.innerHTML = `<div style="padding:32px;text-align:center;color:var(--tg-hint)">${esc(msg)}</div>`;
}
