'use strict';

const tg = window.Telegram.WebApp;
tg.ready();
tg.expand();

// ── State ────────────────────────────────────────────────────────────────────
let currentUserUUID = null;
let currentUserName = '';
let currentUserIsActive = true;
let currentVlessURI = null;
let usersCache = [];
let monthlyChart = null;
let usersChart = null;
let detailTrafficChart = null;
let detailConnectionsChart = null;
let noteSaveTimer = null;

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
  if (name === 'history') loadAuditHistory();
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
  const showDisabled = document.getElementById('users-show-disabled')?.checked || false;
  const onlySuspicious = document.getElementById('users-only-suspicious')?.checked || false;
  const q = (document.getElementById('users-search')?.value || '').trim().toLowerCase();
  const filtered = (users || [])
    .filter(u => showDisabled || u.is_active !== false)
    .filter(u => !onlySuspicious || !!u._suspicious)
    .filter(u => {
      if (!q) return true;
      return `${u.name || ''} ${u.note || ''}`.toLowerCase().includes(q);
    })
    .sort((a, b) => {
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
    item.className = 'user-item';
    item.onclick = () => openUserDetail(u);
    const initial = (u.name || '?')[0].toUpperCase();
    const traffic = formatBytes(u.total_bytes || 0);
    const badge = lastSeenBadge(u.last_seen_at);
    const disabled = u.is_active === false;
    const statusChip = disabled ? '<span class="status-chip">ОТКЛЮЧЕН</span>' : '';
    item.innerHTML = `
      <div class="user-avatar">${initial}</div>
      <div class="user-info">
        <div class="user-name-row">
          <div class="user-name">${esc(u.name)}</div>
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
  try {
    await api('POST', '/api/users', { name });
    showScreen('users');
    await loadUsers();
    showToast(`Пользователь "${name}" создан.`);
  } catch (e) {
    showToast('Ошибка: ' + e.message);
  }
}

// ── User detail ──────────────────────────────────────────────────────────────
async function openUserDetail(u) {
  currentUserUUID = u.uuid;
  currentUserName = u.name || '';
  currentUserIsActive = u.is_active !== false;
  currentVlessURI = null;
  document.getElementById('detail-name').textContent = (u.name || u.uuid) + (currentUserIsActive ? '' : ' · отключён');
  document.getElementById('detail-rename-input').value = u.name || '';
  document.getElementById('detail-rename-card').style.display = 'none';
  document.getElementById('detail-enable-btn').style.display = currentUserIsActive ? 'none' : '';
  document.getElementById('detail-traffic').textContent = formatBytes(u.total_bytes || 0) + ' этот месяц';
  document.getElementById('detail-vless-uri').textContent = 'Загрузка…';
  document.getElementById('qr-container').innerHTML = '';
  const noteInput = document.getElementById('detail-note-input');
  noteInput.value = u.note || '';
  noteInput.oninput = scheduleCurrentUserNoteSave;
  document.getElementById('detail-note-status').textContent = u.note ? 'Сохранено' : 'Без заметки';
  document.getElementById('detail-month-input').value = currentMonthInputValue();
  showScreen('user-detail');

  await loadCurrentUserTrafficByMonth();
  await loadCurrentUserLeak();

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

function beginRenameUser() {
  if (!currentUserUUID) return;
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

function scheduleCurrentUserNoteSave() {
  const status = document.getElementById('detail-note-status');
  status.textContent = 'Сохраняем...';
  if (noteSaveTimer) clearTimeout(noteSaveTimer);
  noteSaveTimer = setTimeout(saveCurrentUserNote, 500);
}

async function saveCurrentUserNote() {
  if (!currentUserUUID) return;
  const note = document.getElementById('detail-note-input').value;
  const status = document.getElementById('detail-note-status');
  try {
    const res = await api('PATCH', `/api/users/${currentUserUUID}`, { note });
    const updated = (res && res.user) ? res.user : null;
    const idx = usersCache.findIndex(u => u.uuid === currentUserUUID);
    if (idx >= 0) {
      usersCache[idx] = { ...usersCache[idx], note: updated ? updated.note : note };
    }
    status.textContent = 'Сохранено';
  } catch (e) {
    status.textContent = 'Ошибка сохранения';
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
    summary.textContent = `Concurrent IPs: ${data.concurrent_ips} · Unique IPs 24h: ${data.unique_ips_24h}` +
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
    const idx = usersCache.findIndex(u => u.uuid === currentUserUUID);
    if (idx >= 0) usersCache[idx] = { ...usersCache[idx], _suspicious: !!data.suspicious };
    renderUsers(usersCache);
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
    document.getElementById('detail-enable-btn').style.display = 'none';
    document.getElementById('detail-name').textContent = currentUserName;
    showToast('Пользователь включён.');
    renderUsers(usersCache);
  } catch (e) {
    showToast('Ошибка включения: ' + e.message);
  }
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
  const user = usersCache.find(u => u.uuid === currentUserUUID) || {};
  const threshold = Number(user.leak_max_concurrent_ips || 2);
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
    } catch (e) {
      showToast('Ошибка отключения: ' + e.message);
    }
  });
}

// ── Diagnostics ───────────────────────────────────────────────────────────────
async function loadDiagnostics() {
  const loader = document.getElementById('diag-loader');
  const list = document.getElementById('diag-sessions-list');
  loader.style.display = 'block';
  try {
    const [sessions, alerts] = await Promise.all([
      api('GET', '/api/diag/sessions?limit=20'),
      api('GET', '/api/alerts/recent?limit=20').catch(() => []),
    ]);
    renderDiagSessions(sessions || []);
    renderDiagAlerts(alerts || []);
  } catch (e) {
    list.className = 'diag-list empty';
    list.textContent = `Сессии недоступны: ${e.message}`;
  } finally {
    loader.style.display = 'none';
  }
}

async function runProbe() {
  const status = document.getElementById('diag-probe-status');
  status.textContent = 'Выполняем замер...';
  try {
    const data = await api('GET', '/api/diag/probe');
    if (data.error) {
      status.textContent = `Ошибка: ${data.error}`;
    } else {
      const when = formatTime(data.measured_at || data.MeasuredAt);
      status.textContent = `Exit ${data.exit_addr || data.ExitAddr}: ${data.bridge_to_exit_tcp_ms || data.BridgeToExitTCPMs} ms · ${when}`;
    }
    await loadDiagnostics();
  } catch (e) {
    status.textContent = `Ошибка замера: ${e.message}`;
  }
}

function renderDiagSessions(sessions) {
  const list = document.getElementById('diag-sessions-list');
  if (!Array.isArray(sessions) || sessions.length === 0) {
    list.className = 'diag-list empty';
    list.textContent = 'Пока нет данных.';
    return;
  }
  list.className = 'diag-list';
  list.innerHTML = '';
  sessions.forEach(s => {
    const item = document.createElement('div');
    item.className = 'diag-item';
    const started = formatTime(s.started_at || s.StartedAt);
    const destination = s.destination || s.Destination || '—';
    const stageStr = formatStages(s.stages_us || s.StagesUS || {});
    item.innerHTML = `
      <div class="diag-item-title">#${esc(String(s.session_id || s.SessionID || ''))} · ${esc(destination)}</div>
      <div class="diag-item-meta">${esc(started)}</div>
      <div class="diag-item-meta">${esc(stageStr)}</div>
    `;
    list.appendChild(item);
  });
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

async function loadHealth() {
  const status = document.getElementById('health-status');
  if (!status) return;
  try {
    const h = await api('GET', '/api/health');
    const latency = h.exit_latency_ms || h.ExitLatencyMS;
    const checked = formatTime(h.checked_at || h.CheckedAt);
    status.textContent = `Bridge ${h.bridge || h.Bridge} · Exit ${h.exit || h.Exit}` +
      (latency ? ` · ${latency} ms` : '') +
      (checked ? ` · ${checked}` : '');
  } catch (e) {
    status.textContent = 'Health недоступен: ' + e.message;
  }
}

function formatStages(stages) {
  const entries = Object.entries(stages || {});
  if (entries.length === 0) return 'Без этапов';
  return entries
    .slice(0, 4)
    .map(([k, v]) => `${k}: ${(Number(v) / 1000).toFixed(2)}ms`)
    .join(' · ');
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

async function loadAuditHistory() {
  const list = document.getElementById('history-list');
  if (!list) return;
  list.className = 'diag-list empty';
  list.textContent = 'Загрузка…';
  try {
    const rows = await api('GET', '/api/audit/history?limit=100');
    if (!rows || rows.length === 0) {
      list.className = 'diag-list empty';
      list.textContent = 'История пуста.';
      return;
    }
    list.className = 'diag-list';
    list.innerHTML = '';
    rows.forEach(r => {
      const item = document.createElement('div');
      item.className = 'diag-item';
      item.innerHTML = `
        <div class="diag-item-title">${esc(r.Action || r.action)}</div>
        <div class="diag-item-meta">admin: ${esc(String(r.TelegramID || r.telegram_id))} · ${esc(formatTime(r.CreatedAt || r.created_at))}</div>
      `;
      list.appendChild(item);
    });
  } catch (e) {
    list.className = 'diag-list empty';
    list.textContent = 'Ошибка загрузки истории: ' + e.message;
  }
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
