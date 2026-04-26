'use strict';

const tg = window.Telegram.WebApp;
tg.ready();
tg.expand();

// ── State ────────────────────────────────────────────────────────────────────
let currentUserUUID = null;
let currentUserName = '';
let currentUserIsActive = true;
let currentUserKind = 'vless';
let currentVlessURI = null;
let currentSocks5URI = null;
let usersCache = [];
let monthlyChart = null;
let usersChart = null;
let detailTrafficChart = null;
let detailConnectionsChart = null;

// IP timeline reference line for concurrent IPs (keep in sync with defaultLeakMaxConcurrent in internal/bot/leak.go)
const LEAK_CONCURRENT_IP_THRESHOLD = 5;

const LEGACY_SOCKS_UUID = '_legacy_socks';

// ── Init ─────────────────────────────────────────────────────────────────────
(async function init() {
  try {
    await checkAuth();
    await loadStats();
    await loadUsers();
    loadSettingsMe();
    setInterval(loadHealth, 30000);
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
  if (name === 'diag') loadDiagnostics();
  if (name === 'settings') loadSettingsMe();
}

function showAddUser() {
  showScreen('add-user');
  document.getElementById('new-user-name').value = '';
  const vless = document.getElementById('new-user-kind-vless');
  if (vless) vless.checked = true;
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
    loadHealth();
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
    const searchWrap = document.getElementById('users-search-wrap');
    if (searchWrap) {
      searchWrap.style.display = usersCache.length < 10 ? 'none' : '';
    }
    const toggleWrap = document.getElementById('users-toggle-disabled-wrap');
    if (toggleWrap) {
      const hasDisabled = usersCache.some(u => u.is_active === false);
      toggleWrap.style.display = hasDisabled ? '' : 'none';
    }
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
  const q = (document.getElementById('users-search')?.value || '').trim().toLowerCase();
  const showDisabled = !!document.getElementById('users-toggle-disabled')?.checked;
  const filtered = (users || [])
    .filter(u => {
      if (!showDisabled && u.is_active === false) return false;
      if (!q) return true;
      return (u.name || '').toLowerCase().includes(q);
    })
    .sort((a, b) => {
      // Active users first, then by last_seen desc; disabled go to the bottom.
      const da = a.is_active === false ? 1 : 0;
      const db = b.is_active === false ? 1 : 0;
      if (da !== db) return da - db;
      const ta = a.last_seen_at ? new Date(a.last_seen_at).getTime() : 0;
      const tb = b.last_seen_at ? new Date(b.last_seen_at).getTime() : 0;
      return tb - ta;
    });
  if (filtered.length === 0) {
    list.innerHTML = '<div class="empty">Нет пользователей.<br>Нажмите + Добавить.</div>';
    return;
  }
  filtered.forEach(u => {
    const item = document.createElement('div');
    const disabled = u.is_active === false;
    item.className = 'user-item' + (disabled ? ' user-item-disabled' : '');
    item.onclick = () => openUserDetail(u);
    const initial = (u.name || '?')[0].toUpperCase();
    const traffic = formatBytes(u.total_bytes || 0);
    const badge = lastSeenBadge(u.last_seen_at);
    const statusChip = disabled ? '<span class="status-chip">ОТКЛЮЧЕН</span>' : '';
    const kind = String(u.kind || 'vless').toLowerCase();
    let kindChips = '';
    if (kind === 'socks5') kindChips += '<span class="kind-chip">SOCKS5</span>';
    if (u.uuid === LEGACY_SOCKS_UUID) kindChips += '<span class="system-chip">SYSTEM</span>';
    item.innerHTML = `
      <div class="user-avatar">${initial}</div>
      <div class="user-info">
        <div class="user-name-row">
          <div class="user-name">${esc(u.name)}</div>
          ${kindChips}
          ${statusChip}
        </div>
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
  if (!name) { showToast('Введите имя.'); return; }
  const kind = document.querySelector('input[name="new-user-kind"]:checked')?.value || 'vless';
  try {
    await api('POST', '/api/users', { name, kind });
    showScreen('users');
    await loadUsers();
    showToast(kind === 'socks5' ? `SOCKS5 «${name}» создан.` : `Клиент «${name}» создан.`);
  } catch (e) {
    showToast('Ошибка: ' + e.message);
  }
}

// ── User detail ──────────────────────────────────────────────────────────────
async function openUserDetail(u) {
  currentUserUUID = u.uuid;
  currentUserName = u.name || '';
  currentUserIsActive = u.is_active !== false;
  currentUserKind = String(u.kind || 'vless').toLowerCase();
  currentVlessURI = null;
  currentSocks5URI = null;

  const editBtn = document.getElementById('detail-edit-btn');
  if (editBtn) editBtn.style.display = u.uuid === LEGACY_SOCKS_UUID ? 'none' : '';

  const vlessCard = document.getElementById('detail-config-vless');
  const socksCard = document.getElementById('detail-config-socks5');
  if (currentUserKind === 'socks5') {
    if (vlessCard) vlessCard.style.display = 'none';
    if (socksCard) socksCard.style.display = '';
    document.getElementById('detail-vless-uri').textContent = '—';
    document.getElementById('qr-container').innerHTML = '';
    document.getElementById('detail-socks5-uri').textContent = 'Загрузка…';
    document.getElementById('qr-container-socks5').innerHTML = '';
  } else {
    if (vlessCard) vlessCard.style.display = '';
    if (socksCard) socksCard.style.display = 'none';
    document.getElementById('detail-vless-uri').textContent = 'Загрузка…';
    document.getElementById('qr-container').innerHTML = '';
    document.getElementById('detail-socks5-uri').textContent = '—';
    document.getElementById('qr-container-socks5').innerHTML = '';
  }

  document.getElementById('detail-name').textContent = (u.name || u.uuid) + (currentUserIsActive ? '' : ' · отключён');
  document.getElementById('detail-rename-input').value = u.name || '';
  document.getElementById('detail-rename-card').style.display = 'none';
  syncDetailActions();
  document.getElementById('detail-traffic').textContent = formatBytes(u.total_bytes || 0) + ' этот месяц';
  document.getElementById('detail-month-input').value = currentMonthInputValue();
  showScreen('user-detail');

  await loadCurrentUserTrafficByMonth();
  await loadCurrentUserLeak();

  try {
    const cfg = await api('GET', `/api/users/${u.uuid}/config`);
    currentVlessURI = cfg.vless_uri || cfg.VLESSURI || '';
    currentSocks5URI = cfg.socks5_uri || cfg.Socks5URI || '';
    if (currentUserKind === 'socks5') {
      document.getElementById('detail-socks5-uri').textContent = currentSocks5URI || '—';
      const meta = document.getElementById('detail-socks5-meta');
      if (meta) {
        const parts = [];
        const user = cfg.username || cfg.Username;
        const port = cfg.port || cfg.Port;
        if (user) parts.push('User: ' + user);
        if (port) parts.push('Port: ' + port);
        meta.textContent = parts.join(' · ');
      }
      if (currentSocks5URI && window.QRCode) {
        const wrap = document.getElementById('qr-container-socks5');
        wrap.innerHTML = '';
        QRCode.toCanvas(currentSocks5URI, { width: 220, margin: 2, color: { dark: '#000000', light: '#ffffff' } },
          (err, canvas) => {
            if (!err) wrap.appendChild(canvas);
          });
      }
    } else {
      document.getElementById('detail-vless-uri').textContent = currentVlessURI;
      if (currentVlessURI && window.QRCode) {
        QRCode.toCanvas(currentVlessURI, { width: 220, margin: 2, color: { dark: '#000000', light: '#ffffff' } },
          (err, canvas) => {
            if (!err) document.getElementById('qr-container').appendChild(canvas);
          });
      }
    }
  } catch (e) {
    if (currentUserKind === 'socks5') {
      document.getElementById('detail-socks5-uri').textContent = 'Ошибка загрузки конфигурации.';
    } else {
      document.getElementById('detail-vless-uri').textContent = 'Ошибка загрузки конфигурации.';
    }
  }
}

function beginRenameUser() {
  if (!currentUserUUID || currentUserUUID === LEGACY_SOCKS_UUID) return;
  const card = document.getElementById('detail-rename-card');
  card.style.display = '';
  const input = document.getElementById('detail-rename-input');
  input.value = currentUserName || '';
  input.focus();
  input.select();
}

function cancelRenameUser() {
  const card = document.getElementById('detail-rename-card');
  card.style.display = 'none';
}

async function saveRenameUser() {
  if (!currentUserUUID) return;
  const input = document.getElementById('detail-rename-input');
  const newName = input.value.trim();
  if (!newName) {
    showToast('Имя не может быть пустым.');
    return;
  }
  try {
    const res = await api('PATCH', `/api/users/${currentUserUUID}`, { name: newName });
    const updated = (res && res.user) ? res.user : { uuid: currentUserUUID, name: newName };
    const idx = usersCache.findIndex(u => u.uuid === currentUserUUID);
    if (idx >= 0) {
      usersCache[idx] = { ...usersCache[idx], name: updated.name || newName };
    }
    currentUserName = updated.name || newName;
    document.getElementById('detail-name').textContent = currentUserName;
    cancelRenameUser();
    showToast('Имя обновлено.');
    renderUsers(usersCache);
  } catch (e) {
    showToast('Ошибка обновления: ' + e.message);
  }
}

async function loadCurrentUserTrafficByMonth() {
  if (!currentUserUUID) return;
  const month = document.getElementById('detail-month-input').value || currentMonthInputValue();
  try {
    const data = await api('GET', `/api/users/${currentUserUUID}/traffic?month=${month}`);
    const uplink = Number(data.UplinkBytes || data.uplink_bytes || 0);
    const downlink = Number(data.DownlinkBytes || data.downlink_bytes || 0);
    const total = Number(data.TotalBytes || data.total_bytes || (uplink + downlink));
    document.getElementById('detail-traffic').textContent = `${formatBytes(total)} (${month})`;
    renderDetailTrafficChart(month, uplink, downlink, total);
  } catch (e) {
    showToast('Ошибка загрузки трафика: ' + e.message);
  }
}

async function loadCurrentUserLeak() {
  if (!currentUserUUID) return;
  const summary = document.getElementById('detail-leak-summary');
  const list = document.getElementById('detail-leak-signals');
  try {
    const data = await api('GET', `/api/users/${currentUserUUID}/leak?limit=5`);
    const cTh = data.concurrent_threshold ?? LEAK_CONCURRENT_IP_THRESHOLD;
    const uTh = data.unique_ips_24h_threshold ?? 10;
    summary.textContent = `Concurrent: ${data.concurrent_ips} (алерт >${cTh}) · Unique 24ч: ${data.unique_ips_24h} (алерт >${uTh})` +
      (data.suspicious ? ' · подозрение' : ' · норма');
    const signals = data.signals || [];
    if (!signals.length) {
      list.className = 'diag-list empty';
      list.textContent = 'Нет сигналов.';
      return;
    }
    list.className = 'diag-list';
    list.innerHTML = '';
    signals.forEach(s => {
      const item = document.createElement('div');
      item.className = 'diag-item';
      item.innerHTML = `
        <div class="diag-item-title">${esc(s.Kind || s.kind)} · score ${esc(String(s.Score || s.score))}</div>
        <div class="diag-item-meta">${esc(formatTime(s.CreatedAt || s.created_at))}</div>
      `;
      list.appendChild(item);
    });
  } catch (e) {
    summary.textContent = 'Leak-данные недоступны: ' + e.message;
    list.className = 'diag-list empty';
    list.textContent = 'Нет сигналов.';
  }
  await loadCurrentUserConnectionsChart();
}

async function loadCurrentUserConnectionsChart() {
  if (!currentUserUUID) return;
  const window = document.getElementById('detail-connections-window')?.value || '24h';
  try {
    const data = await api('GET', `/api/users/${currentUserUUID}/connections?window=${window}`);
    const points = data.points || [];
    renderConnectionsChart(points);
  } catch (e) {
    showToast('Ошибка загрузки connection-графика: ' + e.message);
  }
}

async function enableCurrentUser() {
  if (!currentUserUUID) return;
  try {
    await api('POST', `/api/users/${currentUserUUID}/enable`);
    const idx = usersCache.findIndex(u => u.uuid === currentUserUUID);
    if (idx >= 0) usersCache[idx] = { ...usersCache[idx], is_active: true, disabled_at: null };
    currentUserIsActive = true;
    syncDetailActions();
    document.getElementById('detail-name').textContent = currentUserName;
    showToast('Пользователь включён.');
    renderUsers(usersCache);
  } catch (e) {
    showToast('Ошибка включения: ' + e.message);
  }
}

// syncDetailActions toggles which action group is visible in the user-detail
// screen: rotate/disable for active users, enable/purge for disabled.
function syncDetailActions() {
  const active = document.getElementById('detail-actions-active');
  const disabled = document.getElementById('detail-actions-disabled');
  if (!active || !disabled) return;
  if (currentUserUUID === LEGACY_SOCKS_UUID) {
    active.style.display = 'none';
    disabled.style.display = 'none';
    return;
  }
  active.style.display = currentUserIsActive ? '' : 'none';
  disabled.style.display = currentUserIsActive ? 'none' : '';
  const rotateBtn = document.getElementById('detail-rotate-btn');
  if (rotateBtn) {
    rotateBtn.textContent = currentUserKind === 'socks5' ? 'Перевыпустить пароль' : 'Перевыпустить ключ';
  }
}

// purgeCurrentUser permanently removes a disabled user (UUID + traffic + leak
// signals + IP observations + notifications). Requires double confirmation.
async function purgeCurrentUser() {
  if (!currentUserUUID) return;
  if (currentUserIsActive) {
    showToast('Сначала отключите пользователя.');
    return;
  }
  const uuid = currentUserUUID;
  const name = currentUserName || uuid;
  tg.showConfirm(`Удалить пользователя "${name}" навсегда? Все данные о трафике будут потеряны.`, confirmed1 => {
    if (!confirmed1) return;
    tg.showConfirm('Это действие необратимо. Точно продолжить?', async confirmed2 => {
      if (!confirmed2) return;
      try {
        await api('DELETE', `/api/users/${uuid}/purge`);
        usersCache = usersCache.filter(u => u.uuid !== uuid);
        currentUserUUID = null;
        showToast('Пользователь удалён.');
        showScreen('users');
        renderUsers(usersCache);
        const toggleWrap = document.getElementById('users-toggle-disabled-wrap');
        if (toggleWrap) {
          const hasDisabled = usersCache.some(u => u.is_active === false);
          toggleWrap.style.display = hasDisabled ? '' : 'none';
        }
      } catch (e) {
        showToast('Ошибка удаления: ' + e.message);
      }
    });
  });
}

function rotateCurrentUserUUID() {
  if (!currentUserUUID) return;
  tg.showConfirm('Все устройства со старым ключом перестанут подключаться. Продолжить?', async confirmed => {
    if (!confirmed) return;
    try {
      const res = await api('POST', `/api/users/${currentUserUUID}/rotate`);
      const newUUID = res && (res.uuid || res.UUID);
      if (!newUUID) throw new Error('не получен новый UUID');
      const idx = usersCache.findIndex(u => u.uuid === currentUserUUID);
      if (idx >= 0) usersCache[idx] = { ...usersCache[idx], uuid: newUUID };
      currentUserUUID = newUUID;
      showToast('Ключ перевыпущен. Обновите конфигурацию на устройствах.');
      await openUserDetail(usersCache[idx] || { uuid: newUUID, name: currentUserName, is_active: currentUserIsActive });
    } catch (e) {
      showToast('Ошибка ротации: ' + e.message);
    }
  });
}

function renderDetailTrafficChart(month, uplink, downlink, total) {
  const ctx = document.getElementById('detail-traffic-chart');
  if (!ctx) return;
  if (detailTrafficChart) {
    detailTrafficChart.destroy();
    detailTrafficChart = null;
  }
  const tickColor = getComputedStyle(document.documentElement)
    .getPropertyValue('--tg-hint').trim() || '#888';
  const gridColor = 'rgba(136,136,136,0.15)';
  const gb = v => +((v || 0) / 1073741824).toFixed(3);
  detailTrafficChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Uplink', 'Downlink', 'Total'],
      datasets: [{
        label: month,
        data: [gb(uplink), gb(downlink), gb(total)],
        backgroundColor: ['rgba(82,136,193,0.75)', 'rgba(96,180,140,0.75)', 'rgba(255,189,89,0.75)'],
        borderRadius: 6,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: tickColor }, grid: { display: false } },
        y: {
          ticks: { color: tickColor, callback: value => `${value} ГБ` },
          grid: { color: gridColor },
        },
      },
    },
  });
}

function renderConnectionsChart(points) {
  const ctx = document.getElementById('detail-connections-chart');
  if (!ctx) return;
  if (detailConnectionsChart) {
    detailConnectionsChart.destroy();
    detailConnectionsChart = null;
  }
  const labels = points.map(p => formatTime(p.BucketStart || p.bucket_start));
  const values = points.map(p => Number(p.IPs || p.ips || 0));
  const threshold = LEAK_CONCURRENT_IP_THRESHOLD;
  detailConnectionsChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Concurrent IPs',
          data: values,
          borderColor: 'rgba(82,136,193,1)',
          backgroundColor: 'rgba(82,136,193,0.2)',
          tension: 0.3,
          fill: true,
        },
        {
          label: 'Threshold',
          data: labels.map(() => threshold),
          borderColor: 'rgba(244,67,54,0.95)',
          borderDash: [6, 4],
          pointRadius: 0,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: true } },
      scales: { y: { beginAtZero: true } },
    },
  });
}

function copyVlessURI() {
  if (!currentVlessURI) return;
  navigator.clipboard.writeText(currentVlessURI).then(
    () => showToast('VLESS URI скопирован.'),
    () => showToast('Не удалось скопировать.'),
  );
}

function copySocks5URI() {
  if (!currentSocks5URI) return;
  navigator.clipboard.writeText(currentSocks5URI).then(
    () => showToast('SOCKS5 строка скопирована.'),
    () => showToast('Не удалось скопировать.'),
  );
}

function rotateCurrentUserCredentials() {
  if (!currentUserUUID) return;
  if (currentUserKind === 'socks5') {
    tg.showConfirm('Новый пароль: старые подключения перестанут работать. Продолжить?', async confirmed => {
      if (!confirmed) return;
      try {
        const res = await api('POST', `/api/users/${currentUserUUID}/rotate`);
        const uri = res.socks5_uri || res.Socks5URI;
        if (uri) currentSocks5URI = uri;
        showToast('Пароль перевыпущен.');
        const idx = usersCache.findIndex(x => x.uuid === currentUserUUID);
        if (idx >= 0) usersCache[idx] = { ...usersCache[idx] };
        await openUserDetail(usersCache[idx] || { uuid: currentUserUUID, name: currentUserName, is_active: currentUserIsActive, kind: 'socks5' });
      } catch (e) {
        showToast('Ошибка ротации: ' + e.message);
      }
    });
    return;
  }
  rotateCurrentUserUUID();
}

async function deleteCurrentUser() {
  if (!currentUserUUID) return;
  const user = usersCache.find(u => u.uuid === currentUserUUID);
  const name = user ? user.name : currentUserUUID;
  tg.showConfirm(`Отключить пользователя "${name}"?`, async (confirmed) => {
    if (!confirmed) return;
    try {
      await api('DELETE', `/api/users/${currentUserUUID}`);
      const idx = usersCache.findIndex(u => u.uuid === currentUserUUID);
      if (idx >= 0) {
        usersCache[idx] = { ...usersCache[idx], is_active: false, disabled_at: new Date().toISOString() };
      }
      showScreen('users');
      renderUsers(usersCache);
      const toggleWrap = document.getElementById('users-toggle-disabled-wrap');
      if (toggleWrap) toggleWrap.style.display = '';
    } catch (e) {
      showToast('Ошибка отключения: ' + e.message);
    }
  });
}

// ── Diagnostics ───────────────────────────────────────────────────────────────
async function loadDiagnostics() {
  try {
    const alerts = await api('GET', '/api/alerts/recent?limit=20').catch(() => []);
    renderDiagAlerts(alerts || []);
  } catch (e) {
    const list = document.getElementById('diag-alerts-list');
    if (list) {
      list.className = 'diag-list empty';
      list.textContent = `Алерты недоступны: ${e.message}`;
    }
  }
}

async function runProbe() {
  const summary = document.getElementById('diag-health-summary');
  if (summary) summary.textContent = 'Выполняем замер...';
  try {
    await loadHealth();
    await loadDiagnostics();
  } catch (e) {
    if (summary) summary.textContent = `Ошибка замера: ${e.message}`;
  }
}

async function sendTestAlert() {
  try {
    await api('POST', '/api/alerts/test');
    showToast('Тестовый алерт поставлен в очередь (доставка ~10 сек).');
    await loadDiagnostics();
  } catch (e) {
    showToast('Ошибка: ' + e.message);
  }
}

function renderDiagAlerts(alerts) {
  const list = document.getElementById('diag-alerts-list');
  if (!Array.isArray(alerts) || alerts.length === 0) {
    list.className = 'diag-list empty';
    list.textContent = 'Пока нет данных.';
    return;
  }
  list.className = 'diag-list';
  list.innerHTML = '';
  alerts.forEach(a => {
    const item = document.createElement('div');
    item.className = 'diag-item';
    const when = formatTime(a.created_at || a.CreatedAt);
    const payload = a.payload || a.Payload || {};
    item.innerHTML = `
      <div class="diag-item-title">${esc(a.type || a.Type || 'alert')}</div>
      <div class="diag-item-meta">${esc(when)}</div>
      <div class="diag-item-meta">${esc(payload.text || '')}</div>
    `;
    list.appendChild(item);
  });
}

function pickNode(h, key) {
  const modern = h && h[key];
  if (modern && typeof modern === 'object') return modern;
  return null;
}

function setDot(el, ok) {
  if (!el) return;
  el.classList.remove('ok', 'down');
  el.classList.add(ok ? 'ok' : 'down');
}

function fmtMs(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return '';
  return String(Math.round(n));
}

function applyHealthUI(h) {
  const bridge = pickNode(h, 'bridge') || {};
  const exit = pickNode(h, 'exit') || {};

  const bridgeInternetOk = !!bridge.internet_ok;
  const exitTunnelOk = !!exit.reachable;
  const exitInternetOk = !!exit.internet_ok;

  setDot(document.getElementById('overview-bridge-dot'), bridgeInternetOk);
  setDot(document.getElementById('overview-exit-dot'), exitTunnelOk && exitInternetOk);

  const overviewSummary = document.getElementById('overview-health-summary');
  if (overviewSummary) {
    const parts = [];
    if (!bridgeInternetOk) parts.push('Bridge: нет выхода в интернет');
    if (!exitTunnelOk) parts.push('Tunnel: exit недоступен');
    if (exitTunnelOk && !exitInternetOk) parts.push('Exit: нет выхода в интернет через туннель');
    overviewSummary.textContent = parts.length ? parts.join(' · ') : 'Всё ок';
  }

  setDot(document.getElementById('diag-bridge-dot'), bridgeInternetOk);
  setDot(document.getElementById('diag-exit-dot'), exitTunnelOk && exitInternetOk);

  const bInet = document.getElementById('diag-bridge-internet');
  if (bInet) {
    const ms = fmtMs(bridge.internet_latency_ms ?? bridge.InternetLatencyMS);
    bInet.textContent = ms ? `Internet ${ms} ms` : (bridgeInternetOk ? 'Internet OK' : 'Internet —');
  }
  const eTun = document.getElementById('diag-exit-tunnel');
  if (eTun) {
    const ms = fmtMs(exit.tunnel_latency_ms ?? exit.TunnelLatencyMS);
    eTun.textContent = ms ? `Tunnel ${ms} ms` : (exitTunnelOk ? 'Tunnel OK' : 'Tunnel —');
  }
  const eInet = document.getElementById('diag-exit-internet');
  if (eInet) {
    const ms = fmtMs(exit.internet_latency_ms ?? exit.InternetLatencyMS);
    eInet.textContent = ms ? `Internet ${ms} ms` : (exitInternetOk ? 'Internet OK' : 'Internet —');
  }

  const diagSummary = document.getElementById('diag-health-summary');
  if (diagSummary) {
    const checked = formatTime(h.checked_at || h.CheckedAt);
    diagSummary.textContent = checked ? `Обновлено: ${checked}` : 'Готово';
  }
}

async function loadHealth() {
  try {
    const h = await api('GET', '/api/health');
    applyHealthUI(h);
  } catch (e) {
    const overviewSummary = document.getElementById('overview-health-summary');
    if (overviewSummary) overviewSummary.textContent = 'Health недоступен: ' + e.message;
    setDot(document.getElementById('overview-bridge-dot'), false);
    setDot(document.getElementById('overview-exit-dot'), false);
    setDot(document.getElementById('diag-bridge-dot'), false);
    setDot(document.getElementById('diag-exit-dot'), false);
    const diagSummary = document.getElementById('diag-health-summary');
    if (diagSummary) diagSummary.textContent = 'Health недоступен: ' + e.message;
  }
}

// ── Settings ─────────────────────────────────────────────────────────────────
async function loadSettingsMe() {
  try {
    const me = await api('GET', '/api/me');
    document.getElementById('settings-me').textContent = me.name + (me.username ? ` (@${me.username})` : '');
    await loadAdmins(me.telegram_id);
  } catch (_) {}
}

async function loadAdmins(currentTelegramID) {
  const list = document.getElementById('settings-admins-list');
  try {
    const admins = await api('GET', '/api/admins');
    if (!admins || admins.length === 0) {
      list.className = 'diag-list empty';
      list.textContent = 'Список пуст.';
      return;
    }
    list.className = 'diag-list';
    list.innerHTML = '';
    admins.forEach(a => {
      const item = document.createElement('div');
      item.className = 'diag-item';
      const canRemove = admins.length > 1 && a.TelegramID !== currentTelegramID;
      item.innerHTML = `
        <div class="diag-item-title">${esc(a.TelegramName || `id${a.TelegramID}`)}</div>
        <div class="diag-item-meta">id ${esc(String(a.TelegramID))}</div>
      `;
      if (canRemove) {
        const btn = document.createElement('button');
        btn.className = 'btn danger';
        btn.style.marginTop = '8px';
        btn.style.padding = '8px 12px';
        btn.style.fontSize = '12px';
        btn.textContent = 'Удалить';
        btn.onclick = () => removeAdmin(a.TelegramID);
        item.appendChild(btn);
      }
      list.appendChild(item);
    });
  } catch (e) {
    list.className = 'diag-list empty';
    list.textContent = 'Ошибка загрузки админов: ' + e.message;
  }
}

function removeAdmin(telegramID) {
  tg.showConfirm(`Удалить администратора ${telegramID}?`, async confirmed => {
    if (!confirmed) return;
    try {
      await api('POST', `/api/admins/${telegramID}/remove`);
      await loadSettingsMe();
    } catch (e) {
      showToast('Ошибка удаления: ' + e.message);
    }
  });
}

async function generateInvite() {
  try {
    const res = await api('POST', '/api/admin/invite');
    const box = document.getElementById('invite-token');
    box.textContent = `/start ${res.token}`;
    document.getElementById('invite-result').style.display = 'block';
  } catch (e) {
    showToast('Ошибка: ' + e.message);
  }
}

function copyInviteToken() {
  const text = document.getElementById('invite-token').textContent;
  navigator.clipboard.writeText(text).then(
    () => showToast('Токен скопирован.'),
    () => showToast('Не удалось скопировать.'),
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

function currentMonthInputValue() {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  return `${y}-${m}`;
}

function formatTime(iso) {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso || '');
  return d.toLocaleString('ru-RU', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function showError(msg) {
  document.body.innerHTML = `<div style="padding:32px;text-align:center;color:var(--tg-hint)">${esc(msg)}</div>`;
}

function showToast(msg) {
  let box = document.getElementById('toast-box');
  if (!box) {
    box = document.createElement('div');
    box.id = 'toast-box';
    box.className = 'toast-box';
    document.body.appendChild(box);
  }
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = msg;
  box.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 2600);
}
