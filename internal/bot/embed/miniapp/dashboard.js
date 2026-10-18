"use strict";

// Every panel has its own error state; an unavailable source never becomes a zero.
function panelError(title, retry) {
  return `<div class="card empty-state"><h2>${esc(title)}</h2><p>Данные временно недоступны.</p><button class="btn secondary" id="${retry}">Повторить</button></div>`;
}
function metric(label, value, caption = "") {
  return `<div class="metric"><span>${esc(label)}</span><strong>${esc(value)}</strong><small>${esc(caption)}</small></div>`;
}
function dateLabel(value) {
  const d = new Date(value);
  return value && !Number.isNaN(d.getTime())
    ? d.toLocaleString("ru", {
        day: "numeric",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Нет данных";
}
function latencyLabel(value) {
  return value == null || !Number.isFinite(Number(value))
    ? "нет замера"
    : `${Number(value)} мс`;
}
function healthSummary(h) {
  if (!h) return { label: "Нет данных о серверах", tone: "wait" };
  const good =
    h.bridge?.internet_ok &&
    h.exit?.reachable &&
    h.exit?.internet_ok &&
    !h.selection_degraded &&
    (h.exits || []).every((e) => e.reachable && e.internet_ok);
  return {
    label: good ? "Серверные проверки прошли" : "Требуется внимание",
    tone: good ? "good" : "wait",
  };
}
async function overview() {
  const version = ++viewVersion;
  app.innerHTML = `<div class="page-heading"><div><p class="eyebrow">ПУЛЬТ УПРАВЛЕНИЯ</p><h1>Обзор сети</h1><p class="muted">Трафик, доступ и состояние вашей сети.</p></div><button class="btn secondary compact" id="refresh-overview">Обновить</button></div><section id="overview-summary" class="metrics" aria-label="Сводка">Загружаем сводку…</section><section id="overview-health"></section><div class="section-heading"><h2>Использование подписок</h2><small>Только трафик с известным выходом · UTC</small></div><section id="overview-traffic"></section><div class="dashboard-grid"><section id="overview-history"></section><section id="overview-top"></section></div>`;
  button("refresh-overview", overview);
  const results = await Promise.allSettled([
    api("/api/stats"),
    api("/api/members"),
    api("/api/health"),
    api("/api/members/traffic"),
    api("/api/stats/history?months=12"),
    api("/api/users"),
  ]);
  if (version !== viewVersion || currentTab !== "overview") return;
  const value = (i) =>
    results[i].status === "fulfilled"
      ? (results[i].value ?? ([1, 4, 5].includes(i) ? [] : null))
      : null;
  const stats = value(0),
    members = value(1),
    health = value(2),
    traffic = value(3),
    history = value(4),
    users = value(5);
  document.querySelector("#overview-summary").innerHTML =
    metric(
      "Трафик за месяц",
      stats ? bytes(stats.total_bytes_month) : "—",
      stats
        ? `${stats.total_users ?? "—"} активных конфигов`
        : "Все конфиги сервиса",
    ) +
    metric(
      "Участники",
      members ? members.length : "—",
      "Зарегистрированы через Telegram",
    ) +
    metric(
      "Использовали недавно",
      members ? members.filter(recentlyUsed).length : "—",
      "Трафик за последние 2 минуты",
    ) +
    metric(
      "Ожидают применения",
      members ? members.filter((m) => m.pending).length : "—",
      "Изменения доступа",
    );
  const state = healthSummary(health);
  document.querySelector("#overview-health").innerHTML =
    `<button class="health-banner" id="open-diagnostics"><span><span class="badge ${state.tone}">${esc(state.label)}</span><small>${health ? "Auto · " + esc(health.exit?.name || "Нет выбранного выхода") + " · " + esc(dateLabel(health.checked_at)) : "Открыть диагностику и повторить проверку"}</small></span><span>Диагностика →</span></button>`;
  button("open-diagnostics", async () => {
    selectTab("service");
    await diagnostics();
  });
  const target = document.querySelector("#overview-traffic");
  if (traffic) {
    renderTrafficChart(target, traffic);
  } else {
    target.innerHTML = panelError("Использование подписок", "retry-traffic");
    button("retry-traffic", overview);
  }
  document.querySelector("#overview-history").innerHTML = history
    ? historyHTML(history)
    : panelError("История по месяцам", "retry-history");
  document.querySelector("#overview-top").innerHTML = users
    ? rankingHTML(users)
    : panelError("Трафик по конфигам", "retry-top");
  button("retry-history", overview);
  button("retry-top", overview);
  bindBars(document.querySelector("#overview-history"));
  document
    .querySelectorAll("[data-config]")
    .forEach(
      (el) =>
        (el.onclick = () =>
          configDetail(users.find((u) => u.uuid === el.dataset.config))),
    );
}
function historyHTML(rows) {
  const sorted = [...rows].sort((a, b) => a.Year - b.Year || a.Month - b.Month);
  const points = sorted.map((r) => ({
    label: new Date(Date.UTC(r.Year, r.Month - 1, 1)).toLocaleDateString("ru", {
      month: "short",
      year: "2-digit",
      timeZone: "UTC",
    }),
    value: Number(r.TotalBytes) || 0,
  }));
  return `<div class="card"><p class="eyebrow">ДИНАМИКА</p><h2>Последние 12 месяцев</h2><p class="muted">Весь учтённый трафик сервиса, включая ручные конфиги.</p>${barsHTML(points, "История трафика по месяцам")}</div>`;
}
function barsHTML(points, label) {
  if (!points.length)
    return '<p class="empty-state">Истории за этот период пока нет.</p>';
  const peak = Math.max(1, ...points.map((p) => p.value));
  return `<div class="chart-scale"><span>${bytes(peak === 1 ? 0 : peak)}</span><span>0</span></div><div class="usage-chart history-chart" aria-label="${esc(label)}">${points.map((p) => `<button class="chart-column" data-chart-detail="${esc((p.detail || p.label) + " · " + bytes(p.value))}" aria-label="${esc((p.detail || p.label) + " · " + bytes(p.value))}" title="${esc((p.detail || p.label) + " · " + bytes(p.value))}"><span style="height:${(Math.max(0, p.value) / peak) * 100}%"></span></button>`).join("")}</div><div class="chart-axis"><span>${esc(points[0].label)}</span><span>${esc(points[points.length - 1].label)}</span></div><p class="chart-selection" aria-live="polite">Выберите столбец для подробностей</p>`;
}
function bindBars(target) {
  target.querySelectorAll("[data-chart-detail]").forEach(
    (el) =>
      (el.onclick = () => {
        target.querySelector(".chart-selection").textContent =
          el.dataset.chartDetail;
      }),
  );
}
function rankingHTML(users) {
  const ranked = [...users]
    .filter((u) => u.total_bytes > 0)
    .sort((a, b) => b.total_bytes - a.total_bytes)
    .slice(0, 8);
  const max = ranked[0]?.total_bytes || 1;
  return `<div class="card"><p class="eyebrow">ТЕКУЩИЙ МЕСЯЦ</p><h2>Трафик по конфигам</h2><p class="muted">Топ-8 ключей доступа. Откройте конфиг, чтобы увидеть его историю.</p>${ranked.map((u, i) => `<button class="ranking-row" data-config="${esc(u.uuid)}"><span class="rank">${i + 1}</span><span class="ranking-content"><span class="row"><strong>${esc(u.name || "Без имени")}</strong><small>${bytes(u.total_bytes)}</small></span><meter min="0" max="${max}" value="${u.total_bytes}" aria-label="${esc(u.name)}: ${bytes(u.total_bytes)}"></meter></span></button>`).join("") || '<p class="empty-state">Трафика пока нет.</p>'}</div>`;
}
async function diagnostics() {
  clearTimeout(refreshTimer);
  currentTab = "service";
  const version = ++viewVersion;
  app.innerHTML = `<p class="eyebrow">ИНФРАСТРУКТУРА</p><h1>Сервис</h1><div class="section-tabs"><button id="servers-view">Серверы</button><button class="active" id="diagnostics-view">Диагностика</button></div><div class="page-heading"><p class="muted">Проверки с сервера. Подключение устройства проверяйте в Happ.</p><button class="btn secondary compact" id="refresh-diagnostics">Обновить</button></div><section id="network-health"></section><section id="network-alerts"></section>`;
  button("servers-view", () => {
    viewVersion++;
    return service();
  });
  button("refresh-diagnostics", diagnostics);
  const [health, alerts, replicas] = await Promise.allSettled([
    api("/api/health"),
    api("/api/alerts/recent?limit=10"),
    api("/api/cloud/replicas"),
  ]);
  if (version !== viewVersion) return;
  const target = document.querySelector("#network-health");
  const primaryReachable =
    replicas.status === "fulfilled" &&
    Array.isArray(replicas.value) &&
    replicas.value.some((replica) => replica.source === "primary");
  if (health.status === "fulfilled") {
    const h = health.value,
      state = healthSummary(h),
      exits = h.exits?.length ? h.exits : h.exit ? [h.exit] : [];
    target.innerHTML = `<div class="card"><div class="row wrap"><h2>Состояние сети</h2><span class="badge ${state.tone}">${esc(state.label)}</span></div><small>Проверено: ${esc(dateLabel(h.checked_at))}</small><div class="route-row"><span>Bridge · интернет<small>Задержка ${latencyLabel(h.bridge?.internet_latency_ms)}</small></span><strong class="${h.bridge?.internet_ok ? "good" : "bad"}">${h.bridge?.internet_ok ? "Доступен" : "Недоступен"}</strong></div><div class="route-row"><span>Primary PostgreSQL · database<small>Отдельный сервер · источник наблюдения standby</small></span><span class="badge ${primaryReachable ? "good" : "wait"}">${primaryReachable ? "Доступен" : "Состояние неизвестно"}</span></div>${exits.map((e) => `<div class="route-row"><span>${esc(e.name || e.id)}<small>${e.active ? "Активный выход" : "Резервный выход"} · туннель ${latencyLabel(e.tunnel_latency_ms)} · интернет ${latencyLabel(e.internet_latency_ms)}</small></span><span class="badge ${e.reachable && e.internet_ok ? "good" : "bad"}">${e.reachable && e.internet_ok ? "Доступен" : e.reachable ? "Нет интернета" : "Нет туннеля"}</span></div>`).join("")}${ingressHealthHTML(h.public_ingresses || [])}</div>`;
  } else {
    target.innerHTML = panelError("Состояние сети", "retry-health");
    button("retry-health", diagnostics);
  }
  document.querySelector("#network-alerts").innerHTML =
    alerts.status === "fulfilled"
      ? alertsHTML(alerts.value)
      : panelError("Последние события", "retry-alerts");
  button("retry-alerts", diagnostics);
}
function alertsHTML(alerts) {
  const names = {
    exit_down: "Выход недоступен",
    exit_up: "Выход восстановлен",
    exit_failover: "Переключение выхода",
    traffic_spike: "Рост трафика",
    token_leak: "Подозрительная активность",
    test: "Проверка уведомлений",
  };
  return `<div class="card"><p class="eyebrow">ЖУРНАЛ</p><h2>Последние события</h2>${
    alerts
      .map((a) => {
        const p = a.payload || a.Payload || {},
          type = a.type || a.Type;
        return `<div class="event"><span class="badge ${p.severity === "critical" ? "bad" : p.severity === "warning" ? "wait" : "good"}">${esc(names[type] || type)}</span><p>${esc(p.text || "")}</p><small>${esc(dateLabel(a.created_at || a.CreatedAt))}</small></div>`;
      })
      .join("") || '<p class="empty-state">Событий пока нет.</p>'
  }</div>`;
}
async function settings() {
  const version = ++viewVersion;
  const [me, admins] = await Promise.all([api("/api/me"), api("/api/admins")]);
  if (version !== viewVersion) return;
  app.innerHTML = `<p class="eyebrow">УПРАВЛЕНИЕ</p><h1>Настройки</h1><p class="muted">Администраторы и уведомления сервиса.</p><div class="card"><h2>Администраторы</h2>${admins.map((a) => `<div class="route-row"><span>${esc(a.TelegramName)}<small>ID ${a.TelegramID}${a.TelegramID === me.telegram_id ? " · это вы" : ""}</small></span>${admins.length > 1 && a.TelegramID !== me.telegram_id ? `<button class="text-button bad" data-remove-admin="${a.TelegramID}">Удалить</button>` : ""}</div>`).join("")}<button class="btn" id="invite-admin">Пригласить администратора</button><small>Административное приглашение даёт управление всем сервисом.</small></div><div class="card"><h2>Уведомления</h2><p class="muted">Проверьте доставку служебных сообщений в Telegram.</p><button class="btn secondary" id="test-alert">Отправить тестовое уведомление</button></div>`;
  button("invite-admin", async () => {
    const r = await api("/api/admin/invite", "POST");
    modal(
      `<h2>Приглашение администратора</h2><p>Один раз. Передайте лично нужному человеку.</p><p class="secret">/start ${esc(r.token)}</p><button class="btn" id="copy-admin">Скопировать команду</button>`,
    );
    button("copy-admin", () => copy("/start " + r.token));
  });
  button("test-alert", async () => {
    await api("/api/alerts/test", "POST");
    notice("Уведомление в очереди. Доставка обычно занимает около 10 секунд.");
  });
  document.querySelectorAll("[data-remove-admin]").forEach(
    (el) =>
      (el.onclick = () =>
        confirm(
          "Удалить администратора?",
          "Он потеряет доступ к управлению сервисом. Его VPN-доступ сохранится.",
          "Удалить",
          async () => {
            await api(`/api/admins/${el.dataset.removeAdmin}/remove`, "POST");
            await settings();
          },
        )),
  );
}
async function manualUsers() {
  selectTab("people");
  clearTimeout(refreshTimer);
  const version = ++viewVersion;
  const users = (await api("/api/users")) || [];
  if (version !== viewVersion) return;
  app.innerHTML = `<p class="eyebrow">КЛЮЧИ ДОСТУПА</p><h1>Люди</h1><div class="section-tabs"><button id="back-people">Участники</button><button class="active">Конфиги</button></div><p class="muted">Ручные доступы и профили. Статистика здесь относится к одному ключу, а не ко всем устройствам участника.</p><div class="config-filters"><input id="config-search" aria-label="Поиск конфигов" placeholder="Имя конфига"><label><input type="checkbox" id="config-disabled">Отключённые</label></div><section id="config-list"></section><button class="btn" id="create-config">Создать ручной доступ</button>`;
  button("back-people", () => tab("people"));
  button("create-config", () => editConfigName(null));
  function draw() {
    const q = document.querySelector("#config-search").value.toLowerCase();
    document.querySelector("#config-list").innerHTML =
      users
        .filter(
          (u) =>
            (u.name || "").toLowerCase().includes(q) &&
            (u.is_active || document.querySelector("#config-disabled").checked),
        )
        .map(
          (u) =>
            `<button class="person" data-config="${esc(u.uuid)}"><div class="row"><strong>${esc(u.name || "Без имени")}</strong><span class="badge ${u.is_active ? "good" : "bad"}">${u.is_active ? "Разрешён" : "Отключён"}</span></div><p>${bytes(u.total_bytes)} <small>за месяц</small></p></button>`,
        )
        .join("") || '<p class="empty-state">Конфиги не найдены.</p>';
    document
      .querySelectorAll("[data-config]")
      .forEach(
        (el) =>
          (el.onclick = () =>
            configDetail(users.find((u) => u.uuid === el.dataset.config))),
      );
  }
  document.querySelector("#config-search").oninput = draw;
  document.querySelector("#config-disabled").onchange = draw;
  draw();
}
async function configDetail(user) {
  selectTab("people");
  clearTimeout(refreshTimer);
  const version = ++viewVersion;
  app.innerHTML = `<button class="back-link" id="back-configs">← Все конфиги</button><p class="eyebrow">СТАТИСТИКА КОНФИГА</p><h1>${esc(user.name || "Без имени")}</h1><p class="muted">Последний трафик: ${esc(dateLabel(user.last_seen_at))}</p><div class="metrics">${metric("Всего за месяц", bytes(user.total_bytes))}${metric("Получено", bytes(user.downlink_bytes))}${metric("Отправлено", bytes(user.uplink_bytes))}</div><div class="card"><div class="row wrap"><h2>История использования</h2><label>Период<select id="config-window"><option value="1h">1 час</option><option value="24h" selected>24 часа</option><option value="7d">7 дней</option><option value="30d">30 дней</option></select></label></div><section id="config-history"></section><p class="muted">Сумма отправленного и полученного трафика. Время — локальное.</p></div><div class="card"><h2>Трафик за выбранный месяц</h2><label for="config-month">Месяц</label><input type="month" id="config-month" value="${new Date().toISOString().slice(0, 7)}"><section id="config-monthly"></section></div><section id="config-signals"></section>${configControls(user)}`;
  button("back-configs", manualUsers);
  bindConfigControls(user);
  document.querySelector("#config-month").onchange = () =>
    loadConfigMonth(user, version);
  loadConfigMonth(user, version);
  loadConfigSignals(user, version);
  let sequence = 0;
  async function load() {
    const request = ++sequence,
      target = document.querySelector("#config-history");
    target.textContent = "Загружаем историю…";
    try {
      const data = await api(
        `/api/users/${encodeURIComponent(user.uuid)}/traffic/timeline?window=${document.querySelector("#config-window").value}`,
      );
      if (version !== viewVersion || request !== sequence) return;
      const points = (data.points || []).map((p) => ({
        label: dateLabel(p.BucketStart || p.bucket_start),
        detail:
          dateLabel(p.BucketStart || p.bucket_start) +
          " · ↓ " +
          bytes(p.DownlinkBytes ?? p.downlink_bytes) +
          " · ↑ " +
          bytes(p.UplinkBytes ?? p.uplink_bytes),
        value: Number(
          p.TotalBytes ??
            p.total_bytes ??
            (Number(p.UplinkBytes || p.uplink_bytes) || 0) +
              (Number(p.DownlinkBytes || p.downlink_bytes) || 0),
        ),
      }));
      target.innerHTML = barsHTML(points, "История использования конфига");
      bindBars(target);
    } catch {
      if (version !== viewVersion || request !== sequence) return;
      target.innerHTML = panelError("История использования", "retry-config");
      button("retry-config", load);
    }
  }
  document.querySelector("#config-window").onchange = load;
  await load();
}

function routingHTML(data) {
  const exits = Array.isArray(data.exits) ? data.exits : [];
  const effective = exits.find((exit) => exit.id === data.effective_exit_id);
  const applied = data.application?.state === "applied";
  const branches = exits.map((exit) => {
    const active = effective?.id === exit.id;
    const label = active
      ? applied ? "Авто · текущий выход" : "Авто · ожидает применения"
      : exit.reachable ? "Туннель доступен" : "Туннель недоступен";
    return `<li class="routing-exit${active ? " is-active" : ""}" data-route-exit="${esc(exit.id)}"><span class="routing-node"><strong>${esc(exit.display_name || exit.country_name || "Выход")}</strong>${exit.city ? `<small>${esc(exit.city)}</small>` : ""}<small class="${active && applied ? "good" : !exit.reachable ? "wait" : "muted"}">${label}</small>${quotaKindLabel(exit) ? `<span class="badge">${esc(quotaKindLabel(exit))}</span>` : ""}</span></li>`;
  }).join("");
  return `<p class="eyebrow">МАРШРУТИЗАЦИЯ</p><h2>Схема подключения</h2><p class="muted">Серверный маршрут профиля «Автоматически».</p><div class="routing-map" aria-label="Устройство подключается к Bridge, затем к одному из выходов"><div class="routing-source"><span class="routing-node"><strong>Ваше устройство</strong><small>Happ</small></span><span class="routing-arrow" aria-hidden="true">↓</span><span class="routing-node"><strong>Bridge</strong><small>VPN-вход</small></span></div>${branches ? `<ul class="routing-exits" aria-label="Выходы VPN">${branches}</ul>` : '<p class="empty-state">Выходов пока нет</p>'}</div><p class="${applied && effective ? "good" : "wait"}">${esc(applicationLabel(data.application))}</p>${!effective ? '<p class="wait">Нет подтверждённого выхода. Трафик VPN не проходит.</p>' : ""}${data.route_reason ? `<p class="muted">${esc(routeReasonLabel(data.route_reason))}</p>` : ""}<small id="route-refresh-status">Схема обновляется автоматически.</small><details><summary>Как выбирается выход</summary><p>Профиль «Автоматически» выбирает доступный сервер и возвращается к основному после восстановления. Профиль страны предпочитает её сервер и может переключиться на другой исправный выход с доступной вам квотой.</p><small>Кабинет не видит, какой профиль включён в Happ. Доступность туннеля не гарантирует остаток квоты.</small></details>`;
}

function ingressHealthHTML(ingresses) {
  const phases = {
    public_tls: "Публичный TLS",
    local_backend: "Локальный обработчик",
    server_path_ready: "Серверный маршрут готов",
    descriptor: "Конфигурация подготовлена",
    primary_candidate: "Кандидат на основной вход",
    transport_process: "Транспортный процесс",
  };
  return ingresses
    .filter((i) => i.id === "primary")
    .map(
      (i) =>
        `<div class="route-row"><span>Основной вход<small>${esc(phases[i.phase] || i.phase)}${i.certificate_not_after ? " · сертификат до " + esc(dateLabel(i.certificate_not_after)) : ""}</small></span><span class="badge ${i.ready ? "good" : "wait"}">${i.ready ? "Готов" : "Недоступен"}</span></div>`,
    )
    .join("");
}
