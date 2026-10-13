"use strict";
const tg = window.Telegram?.WebApp;
tg?.ready();
tg?.expand();
function syncTheme() {
  if (tg?.colorScheme && document.documentElement)
    document.documentElement.dataset.theme = tg.colorScheme;
}
syncTheme();
tg?.onEvent?.("themeChanged", syncTheme);
const app = document.querySelector("#app"),
  dialog = document.querySelector("#dialog"),
  nav = document.querySelector("#nav");
const selfMode =
  location.pathname === "/member" ||
  document.body?.dataset.cabinet === "member";
let viewVersion = 0;
let currentPerson = null,
  currentTab = "overview",
  memberCache = [],
  subscription = null,
  subscriptionOwner = null,
  noticeTimer,
  refreshTimer;
const esc = (v) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
async function api(path, method = "GET", body) {
  const r = await fetch(path, {
    method,
    headers: {
      "X-Telegram-Init-Data": tg?.initData || "",
      "Content-Type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  if (!r.ok) {
    const e = new Error(
      r.status === 401
        ? "Откройте кабинет заново из личного чата с ботом."
        : r.status === 403
          ? "Для этого действия нет доступа."
          : r.status === 409
            ? "Состояние изменилось. Обновите экран и повторите действие."
            : "Операция временно недоступна. Попробуйте ещё раз.",
    );
    e.status = r.status;
    if (path.startsWith("/api/cloud/")) {
      try {
        const detail = await r.json();
        if (typeof detail.message === "string" && detail.message.length < 700)
          e.message = detail.message;
      } catch {}
    }
    throw e;
  }
  return r.status === 204 ? null : r.json();
}
function notice(t) {
  const n = document.querySelector("#notice");
  n.textContent = t;
  n.hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => (n.hidden = true), 5000);
}
function button(id, fn) {
  const el = document.getElementById(id);
  if (el)
    el.onclick = async () => {
      el.disabled = true;
      try {
        await fn();
      } catch (e) {
        if (dialog.open) {
          const error = document.getElementById("dialog-error");
          error.textContent = e.message;
          error.hidden = false;
        } else notice(e.message);
      } finally {
        el.disabled = false;
      }
    };
}
function modal(html) {
  dialog.innerHTML =
    '<p id="dialog-error" class="bad" role="alert" hidden></p>' +
    html +
    '<button class="btn secondary" id="close-dialog">Закрыть</button>';
  document.querySelector("#close-dialog").onclick = () => dialog.close();
  dialog.showModal();
}
function confirm(title, text, label, action) {
  modal(
    `<h2>${esc(title)}</h2><p>${esc(text)}</p><button id="confirm-action" class="btn danger">${esc(label)}</button>`,
  );
  button("confirm-action", async () => {
    dialog.close();
    await action();
  });
}
async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    notice("Ссылка скопирована");
  } catch {
    modal(`<h2>Скопируйте ссылку</h2><p class="secret">${esc(text)}</p>`);
  }
}
function openExternal(url) {
  const u = new URL(url);
  if (u.protocol !== "https:") throw new Error("Некорректная ссылка");
  if (tg?.openLink) tg.openLink(u.href);
  else window.open(u.href, "_blank", "noopener,noreferrer");
}
function selectTab(name) {
  currentTab = name;
  location.hash = name;
  window.scrollTo?.(0, 0);
  nav.querySelectorAll("button").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === name);
    b.setAttribute("aria-current", b.dataset.tab === name ? "page" : "false");
  });
}
function status(m) {
  return m.pending
    ? `<span class="badge wait">${m.active ? "Разрешаем доступ" : "Отзываем доступ"} · применяется</span>`
    : m.active
      ? '<span class="badge good">Доступ разрешён</span>'
      : '<span class="badge bad">Доступ отозван</span>';
}
function usage(m, now = Date.now()) {
  if (!m.last_traffic_at) return "Трафик ещё не зафиксирован";
  const at = Date.parse(m.last_traffic_at);
  if (!Number.isFinite(at) || at > now + 30000) return "Активность неизвестна";
  const minutes = Math.max(0, Math.floor((now - at) / 60000));
  if (minutes < 2 && m.active && !m.pending) return "Трафик за последние 2 мин";
  if (minutes < 1) return "Последний трафик: менее минуты назад";
  if (minutes < 60) return `Без трафика ${minutes} мин`;
  if (minutes < 1440) return `Без трафика ${Math.floor(minutes / 60)} ч`;
  return `Без трафика ${Math.floor(minutes / 1440)} дн`;
}
function recentlyUsed(m) {
  return (
    m.active &&
    !m.pending &&
    m.last_traffic_at &&
    Date.now() - Date.parse(m.last_traffic_at) >= 0 &&
    Date.now() - Date.parse(m.last_traffic_at) < 120000
  );
}
async function self() {
  clearTimeout(refreshTimer);
  const data = await api("/api/self");
  document.querySelector("#switch").hidden = !data.is_admin;
  if (!data.registered) {
    app.innerHTML =
      '<h1>Мой VPN</h1><div class="card"><h2>Личного доступа пока нет</h2><p>Для регистрации нужна ссылка из разрешённой группы или именное приглашение.</p>' +
      (data.is_admin
        ? '<a class="btn" href="/#invites">Выдать именное приглашение</a><p class="muted">Администратор может пригласить свой Telegram-аккаунт.</p>'
        : "") +
      "</div>";
    return;
  }
  const m = data.member;
  if (subscriptionOwner !== m.uuid) {
    subscription = null;
    subscriptionOwner = m.uuid;
  }
  const ready = m.active && !m.pending;
  app.innerHTML = `<div class="page-heading"><div><p class="eyebrow">ЛИЧНЫЙ КАБИНЕТ</p><h1>Ваш интернет.<br>Ваши правила.</h1><p class="muted">Одна подписка для всех ваших устройств</p></div></div><div class="member-grid"><div class="card connect-card">${status(m)}<p class="muted">${esc(usage(m))}</p><h2 class="connect-title">${ready ? "Подключитесь через Happ" : m.pending ? "Подтверждаем изменение на сервере" : "Доступ приостановлен"}</h2><p class="muted">${ready ? "Добавьте подписку один раз. Затем включайте VPN в Happ." : m.pending ? "Повторная регистрация не нужна. Дождитесь подтверждения применения." : "Обратитесь к администратору. Новое приглашение не восстановит доступ."}</p>${ready ? '<button class="btn" id="connect">Подключить Happ</button><button class="btn secondary" id="copy-sub">Скопировать подписку</button><small>Не передавайте ссылку другим: она открывает доступ к VPN.</small>' : ""}</div>${ready ? '<div class="card route-card" id="locations">Загружаем локации…</div>' : ""}</div><section id="self-traffic" aria-live="polite">Загружаем статистику…</section><button class="btn secondary" id="refresh-self-traffic">Обновить статистику</button><div class="help-grid"><button class="btn secondary" id="instructions">Как подключить устройство</button><button class="btn secondary" id="help">Не получается подключиться</button></div>`;
  button("instructions", instructions);
  button("help", () =>
    modal(
      "<h2>Проверка подключения</h2><p>Откройте Happ, обновите подписку и включите VPN. При необходимости выберите другой профиль.</p><p>Если ошибка осталась, сообщите администратору устройство, сеть и время ошибки. Не отправляйте подписку, QR-код или ключ.</p>",
    ),
  );
  async function getSubscription() {
    if (!subscription)
      subscription = await api("/api/self/subscription", "POST", {});
    return subscription;
  }
  button("connect", async () =>
    openExternal((await getSubscription()).import_url),
  );
  button("copy-sub", async () => copy((await getSubscription()).url));
  await Promise.all([
    loadSelfTraffic(),
    ready
      ? locations().catch(() => {
          document.querySelector("#locations").innerHTML =
            '<h2>Маршрут временно недоступен</h2><p class="muted">Подключение Happ доступно независимо от этой проверки.</p><button class="btn secondary" id="retry-route">Повторить</button>';
          button("retry-route", locations);
        })
      : Promise.resolve(),
  ]);
  if (m.pending)
    refreshTimer = setTimeout(
      () => self().catch((e) => notice(e.message)),
      5000,
    );
}
async function locations() {
  const data = await api("/api/self/exits");
  const effective = data.exits.find((e) => e.id === data.effective_exit_id);
  const exitLabel = (e) =>
    e
      ? `${esc(e.display_name)}${quotaKindLabel(e) ? ` <span class="badge">${esc(quotaKindLabel(e))}</span>` : ""}`
      : "Нет подтверждённого маршрута";
  document.querySelector("#locations").innerHTML =
    `<p class="eyebrow">МАРШРУТИЗАЦИЯ</p><h2>Автоматический выход</h2><p class="muted">Профиль «Автоматически» выбирает доступный сервер и возвращается к основному после восстановления.</p><p>${esc(applicationLabel(data.application))}</p>${data.route_reason ? `<p class="muted">${esc(routeReasonLabel(data.route_reason))}</p>` : ""}<p>Подтверждённый выход: <strong>${exitLabel(effective)}</strong></p><details><summary>Как работают профили</summary><small>Профиль страны предпочитает её сервер. При отказе или исчерпании лимита он переключается на другой исправный выход, только если на нём осталась ваша квота. После восстановления возвращается к предпочтительной стране.</small>${(data.profiles || []).length ? "<h3>Маршруты профилей Happ</h3>" : ""}${(data.profiles || []).map((p) => {
      const route = data.exits.find((e) => e.id === p.effective_exit_id);
      return `<p>${esc(p.name)} → ${route ? exitLabel(route) : "Маршрут недоступен"}</p>`;
    }).join("")}<small>Кабинет не видит, какой профиль включён на устройстве.</small></details>`;
  if (data.application && data.application.state !== "applied") {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(
      () => locations().catch((e) => notice(e.message)),
      5000,
    );
  }
}
function instructions() {
  modal(
    '<h2>Подключить устройство</h2><label for="device">Ваша система</label><select id="device"><option>iPhone / iPad</option><option>Android</option><option>macOS</option><option>Windows</option><option>Linux</option></select><ol><li>Установите Happ из официального источника.</li><li>Нажмите «Подключить Happ» в личном кабинете.</li><li>Подтвердите импорт и включите VPN.</li></ol><p>Если импорт не открылся, скопируйте подписку и добавьте её в Happ вручную. На своих устройствах используйте одну подписку.</p><a href="https://www.happ.su/" target="_blank" rel="noopener noreferrer">Официальный сайт Happ</a>',
  );
}
async function people() {
  const version = ++viewVersion;
  currentPerson = null;
  clearTimeout(refreshTimer);
  const members = await api("/api/members");
  if (version !== viewVersion) return;
  memberCache = members;
  app.innerHTML =
    '<div class="row"><h1>Люди</h1><button class="btn secondary" style="width:auto" id="invite-shortcut">Пригласить</button></div><div class="section-tabs"><button class="active" id="members-view">Участники</button><button id="manual-users">Конфиги</button></div><input id="search" aria-label="Поиск" placeholder="Имя или Telegram ID"><select id="filter" aria-label="Статус"><option value="all">Все</option><option value="active">Доступ разрешён</option><option value="recent">Недавно использовали</option><option value="unused">Трафика ещё не было</option><option value="disabled">Доступ отозван</option><option value="pending">Применяются</option></select><div id="people-list"></div>';
  button("invite-shortcut", () => tab("invites"));
  button("manual-users", manualUsers);
  document.querySelector("#search").oninput = drawPeople;
  document.querySelector("#filter").onchange = drawPeople;
  drawPeople();
  refreshPeopleLater();
}
function drawPeople() {
  const q = document.querySelector("#search").value.toLowerCase(),
    filter = document.querySelector("#filter").value;
  const list = memberCache.filter(
    (m) =>
      (m.name.toLowerCase().includes(q) || String(m.telegram_id).includes(q)) &&
      (filter === "all" ||
        (filter === "pending" && m.pending) ||
        (filter === "active" && m.active && !m.pending) ||
        (filter === "recent" && recentlyUsed(m)) ||
        (filter === "unused" && !m.last_traffic_at) ||
        (filter === "disabled" && !m.active && !m.pending)),
  );
  document.querySelector("#people-list").innerHTML =
    list
      .map(
        (m) =>
          `<button class="person" data-member="${m.telegram_id}"><div class="person-title"><span class="avatar">${esc((m.name || "?").slice(0, 1))}</span><strong>${esc(m.name)}</strong></div><div class="row"><small>${m.telegram_id} · ${m.source === "group" ? "Из группы" : "По приглашению"}</small>${status(m)}</div><p class="muted">${esc(usage(m))}</p><small>${esc(groupLabel(m))}</small></button>`,
      )
      .join("") || '<p class="muted">Пользователи не найдены</p>';
  document
    .querySelectorAll("[data-member]")
    .forEach(
      (el) =>
        (el.onclick = () =>
          person(
            memberCache.find(
              (m) => String(m.telegram_id) === el.dataset.member,
            ),
          )),
    );
}
function person(m) {
  viewVersion++;
  window.scrollTo?.(0, 0);
  currentPerson = m.telegram_id;
  clearTimeout(refreshTimer);
  app.innerHTML = `<button class="back-link" id="back-people">← Люди</button><div class="person-heading"><h1>${esc(m.name)}</h1><small>ID ${m.telegram_id} · ${esc(groupLabel(m).split(" · проверка")[0])}</small></div><div class="row wrap person-status">${status(m)}<small>${esc(usage(m))}</small></div><section id="person-traffic" aria-live="polite">Загружаем статистику…</section><div class="card person-controls"><h2>Управление доступом</h2><button class="btn ${m.active ? "danger" : ""}" id="toggle-access">${m.active ? "Отключить" : "Включить"} доступ</button><button class="btn secondary" id="reset-access">Сбросить на всех устройствах</button></div>`;
  loadPersonTraffic(m.telegram_id);
  button("back-people", people);
  async function act(action) {
    const updated = await api(`/api/members/${m.telegram_id}/action`, "POST", {
      action,
      expected_uuid: m.uuid,
    });
    subscription = null;
    person(updated);
  }
  button("toggle-access", () =>
    confirm(
      m.active ? "Отключить доступ?" : "Включить доступ?",
      m.active
        ? "Подписка и скачанные через неё конфиги перестанут работать. Ручные конфиги не затрагиваются."
        : "Прежняя подписка и конфиги снова будут действовать.",
      m.active ? "Отключить" : "Включить",
      () => act(m.active ? "disable" : "enable"),
    ),
  );
  button("reset-access", () =>
    confirm(
      "Сбросить доступ на всех устройствах?",
      "Старые конфиги и подписка перестанут работать. Пользователю потребуется заново импортировать подписку.",
      "Сбросить доступ",
      () => act("reset"),
    ),
  );
}
async function invites() {
  const version = ++viewVersion;
  const [group, list] = await Promise.all([
    api("/api/enrollment/group"),
    api("/api/enrollment/invites"),
  ]);
  if (version !== viewVersion) return;
  app.innerHTML = `<p class="eyebrow">УПРАВЛЕНИЕ ДОСТУПОМ</p><h1>Приглашения</h1><p class="muted">Ваш круг. Ваши правила доступа.</p><div class="card"><h2>Именное приглашение</h2><p class="muted">Только выбранному аккаунту. Одно использование, срок — 7 дней.</p><button class="btn" id="native-invite">Выбрать получателя в боте</button><label for="recipient">Или числовой Telegram ID</label><input id="recipient" inputmode="numeric" placeholder="Telegram ID"><button class="btn secondary" id="invite-id">Продолжить</button></div><div class="card"><h2>Закрытая группа</h2><p><strong>${esc(group.title || "Не настроена")}</strong></p><p>${group.enabled ? "Регистрация открыта" : "Регистрация закрыта"}${typeof group.group_url === "string" && group.group_url.startsWith("https://t.me/") ? ` · <a href="${esc(group.group_url)}" target="_blank" rel="noopener noreferrer">Открыть группу ↗</a>` : ""}</p><small>Выход из группы после регистрации не отключает VPN.</small>${group.enabled ? '<button class="btn secondary" id="copy-group">Скопировать общую ссылку</button>' : ""}<button class="btn" id="native-group">Выбрать группу в Telegram</button><details><summary>Ввести ID вручную</summary><label for="group-id">Telegram ID закрытой группы</label><input id="group-id" value="${group.chat_id || ""}" inputmode="numeric"><button class="btn secondary" id="save-group">Проверить и включить</button></details>${group.chat_id ? '<button class="btn secondary" id="disable-group">Закрыть регистрацию</button>' : ""}</div><h2>Выданные приглашения</h2>${list.map((i) => `<div class="card"><strong>${esc(i.recipient_name || "Пользователь Telegram")}</strong><p><a href="tg://user?id=${Number(i.recipient)}">Открыть профиль ↗</a> · <small>ID ${i.recipient}</small></p><p class="muted">${i.used_at ? "Активировано" : i.cancelled_at ? "Отменено" : new Date(i.expires_at) < new Date() ? "Истекло" : "До " + new Date(i.expires_at).toLocaleDateString("ru")}</p>${!i.used_at && !i.cancelled_at ? `<button class="btn secondary" data-cancel="${i.id}">Отменить</button>` : ""}</div>`).join("") || '<p class="muted">Приглашений пока нет</p>'}`;
  button("native-group", async () => {
    await api("/api/enrollment/group-picker", "POST", {});
    notice("Выберите группу в личном чате с ботом.");
    tg?.close();
  });
  button("native-invite", async () => {
    await api("/api/enrollment/picker", "POST", {});
    notice("Откройте личный чат с ботом: там появился выбор получателя.");
    tg?.close();
  });
  button("invite-id", () => {
    const value = document.querySelector("#recipient").value;
    if (!/^[1-9]\d{0,14}$/.test(value))
      throw new Error("Введите числовой Telegram ID");
    confirm(
      "Подтвердите получателя",
      `Пригласить Telegram ID ${value}? Административных прав приглашение не даёт.`,
      "Выдать приглашение",
      async () => {
        const r = await api("/api/enrollment/invites", "POST", {
          recipient: Number(value),
        });
        await copy(r.url);
        notice("Приглашение выдано и скопировано");
        await invites();
      },
    );
  });
  button("copy-group", () => copy(group.url));
  button("save-group", async () => {
    const id = Number(document.querySelector("#group-id").value);
    if (!Number.isSafeInteger(id) || id >= 0)
      throw new Error("Введите отрицательный Telegram ID группы");
    await api("/api/enrollment/group", "PUT", { chat_id: id, enabled: true });
    await invites();
  });
  button("disable-group", () =>
    confirm(
      "Закрыть регистрацию?",
      "Уже выданный доступ сохранится. Именные приглашения продолжат работать.",
      "Закрыть регистрацию",
      async () => {
        await api("/api/enrollment/group", "PUT", {
          chat_id: group.chat_id,
          title: group.title,
          enabled: false,
        });
        await invites();
      },
    ),
  );
  document.querySelectorAll("[data-cancel]").forEach(
    (el) =>
      (el.onclick = () =>
        confirm(
          "Отменить приглашение?",
          "Эта ссылка больше не позволит зарегистрироваться.",
          "Отменить",
          async () => {
            await api(
              `/api/enrollment/invites/${el.dataset.cancel}/cancel`,
              "POST",
              {},
            );
            await invites();
          },
        )),
  );
}
const phases = {
  prepare: "Подготовка",
  creating: "Проверяем создание VPS",
  install: "Установка Ultra",
  verify: "Проверка туннеля",
  publish: "Применение маршрутов",
  replace_old: "Удаление прежнего VPS",
  ready: "Готов",
  unpublish: "Отключение маршрута",
  delete: "Удаление VPS",
  cleanup: "Очистка ресурсов",
};
async function service() {
  const version = ++viewVersion;
  clearTimeout(refreshTimer);
  let ops = [],
    unavailable = false;
  try {
    ops = await api("/api/cloud/operations");
  } catch (e) {
    if (e.status === 401 || e.status === 403) throw e;
    unavailable = true;
  }
  let capacity = null;
  try {
    capacity = await api("/api/cloud/quotas");
  } catch {}
  let replicas = [];
  try {
    replicas = await api("/api/cloud/replicas");
  } catch {}
  if (version !== viewVersion) return;
  app.innerHTML = `<p class="eyebrow">ИНФРАСТРУКТУРА</p><h1>Сервис</h1><div class="section-tabs"><button class="active" id="servers-view">Серверы</button><button id="diagnostics-view">Диагностика</button></div><p class="muted">Управление через Vultr · не более 5 VPS</p><p class="muted">Проверка HTTPS выполняется с bridge через exit. Подключение вашего устройства проверьте в Happ: откройте сайт с включённым VPN.</p><section id="cloud-account" aria-live="polite"></section>${unavailable ? '<div class="card"><h2>Vultr пока не настроен</h2><p>Для автоматизации нужны серверный API-ключ, SSH-ключ и настройки исполнителя.</p></div>' : '<button class="btn" id="create-server">Создать exit</button>'}${ops
    .filter((o) => o.state !== "deleted" && o.state !== "cancelled")
    .map(
      (o) =>
        `<div class="card"><div class="row"><h2>${esc(o.offer.region.city)}</h2><span class="badge ${o.state === "ready" ? "good" : o.state === "failed" || o.state === "unknown" ? "bad" : "wait"}">${esc(serverStateLabel(o, capacity))}</span></div><p>${esc(o.offer.plan.id)} · $${o.offer.price.monthly_cost}/месяц</p><p class="muted">${esc(serverBillingLabel(o))}</p>${o.error ? `<p class="bad">${esc(o.error_message || o.error)}</p>` : ""}${o.state === "ready" && !o.serves_subscription_ingress ? `<button class="btn secondary" data-replace="${esc(o.id)}">Сменить регион</button>` : ""}${o.state === "failed" || o.state === "unknown" ? `<button class="btn secondary" data-action="retry" data-op="${esc(o.id)}">Повторить проверку / продолжить</button>` : ""}<button class="btn secondary" data-events="${esc(o.id)}">Журнал операции</button>${o.serves_subscription_ingress ? "<p>Обслуживает подписки · перед удалением или заменой перенесите HTTPS-вход</p>" : o.instance_id ? `<button class="btn danger" data-action="delete" data-op="${esc(o.id)}">Удалить сервер</button>` : o.phase === "prepare" ? `<button class="btn secondary" data-action="cancel" data-op="${esc(o.id)}">Отменить создание</button>` : ""}</div>`,
    )
    .join(
      "",
    )}${capacity ? serverCapacityHTML(capacity) : "<p>Состояние выходов временно недоступно</p>"}<h2>Копии базы данных</h2><p class="muted">Основная БД на bridge. Восстановление — вручную.</p>${replicas.map((r) => `<div class="card"><strong>${esc(r.name)}</strong><p>${esc({ streaming: "Копия обновляется", syncing: "Первичная синхронизация", insufficient_space: "Недостаточно места", lagging: "Копия отстаёт", disconnected: "Нет потока репликации", unexpected_primary: "БД переведена в основную — требуется ручная проверка", error: "Копия БД недоступна: требуется проверка SSH/PostgreSQL", not_configured: "Ещё не настроена" }[r.state] || r.state)}</p><small>${r.free_bytes > 0 ? `Свободно: ${(r.free_bytes / 1073741824).toFixed(1)} ГБ` : "Свободное место: нет данных"}${r.required_bytes > 0 ? ` · нужно для копии: ${(r.required_bytes / 1073741824).toFixed(1)} ГБ` : ""}</small></div>`).join("") || '<p class="muted">Состояние копий пока недоступно</p>'}<p class="muted">Узлы, настроенные вручную, обслуживаются через локальный установщик. Они продолжают участвовать в маршрутах.</p><button class="btn secondary" id="refresh-service">Обновить</button>`;
  button("diagnostics-view", diagnostics);
  loadCloudAccount();
  document
    .querySelectorAll("[data-events]")
    .forEach(
      (el) =>
        (el.onclick = () =>
          operationEvents(el.dataset.events).catch((e) => notice(e.message))),
    );
  button("create-server", () => serverOffer(""));
  button("refresh-service", service);
  document
    .querySelectorAll("[data-replace]")
    .forEach(
      (el) =>
        (el.onclick = () =>
          serverOffer(el.dataset.replace).catch((e) => notice(e.message))),
    );
  document.querySelectorAll("[data-op]").forEach(
    (el) =>
      (el.onclick = () => {
        const action = el.dataset.action;
        confirm(
          action === "delete"
            ? "Удалить платный сервер?"
            : "Продолжить операцию?",
          action === "delete"
            ? "Сначала отключим маршрут. Удаление VPS необратимо; настройки локации сохранятся для резервного маршрута."
            : "Повтор продолжит сохранённую операцию. При неизвестном результате покупка не повторяется.",
          action === "delete" ? "Удалить" : "Продолжить",
          async () => {
            await api(`/api/cloud/operations/${el.dataset.op}/action`, "POST", {
              action,
            });
            await service();
          },
        );
      }),
  );
  if (ops.some((o) => o.state === "pending" || o.state === "unknown"))
    refreshTimer = setTimeout(() => {
      if (currentTab === "service") service().catch((e) => notice(e.message));
    }, 5000);
}
async function serverOffer(replace) {
  const c = await api("/api/cloud/catalog");
  modal(
    `<h2>${replace ? "Сменить регион" : "Новый exit Vultr"}</h2><label for="region">Регион</label><select id="region">${c.regions.map((r) => `<option value="${esc(r.id)}" ${r.id === "fra" ? "selected" : ""}>${esc(r.city)} · ${esc(r.country)}</option>`).join("")}</select><p>Тариф: 1 vCPU, 1 ГБ RAM, 25 ГБ SSD. Наличие и региональную цену проверим перед подтверждением.</p><button class="btn" id="quote">Проверить цену</button>`,
  );
  button("quote", async () => {
    const offer = await api("/api/cloud/offers", "POST", {
      region: document.querySelector("#region").value,
      plan: "vc2-1c-1gb",
      replace_id: replace,
    });
    dialog.close();
    modal(
      `<h2>Подтвердите покупку</h2><p>${esc(offer.region.city)} · ${esc(offer.plan.id)}</p><p><strong>$${offer.price.monthly_cost}/месяц · $${offer.price.hourly_cost}/час</strong></p><p>Трафик тарифа: ${offer.plan.bandwidth} ГБ. Квота начисляется по правилам Vultr; налоги и перерасход оплачиваются отдельно.</p><p class="muted">Предложение действует 5 минут. ${replace ? "Новый сервер занимает дополнительный слот; старый удалим только после проверки и переключения." : ""}</p><button class="btn" id="buy">Подтвердить создание платного VPS</button>`,
    );
    button("buy", async () => {
      await api(`/api/cloud/offers/${offer.id}/confirm`, "POST", {});
      dialog.close();
      await service();
    });
  });
}
async function tab(name) {
  clearTimeout(refreshTimer);
  selectTab(name);
  viewVersion++;
  currentPerson = null;
  app.innerHTML =
    '<div class="loading-state" role="status">Загружаем данные…</div>';
  try {
    await (
      { overview, people, invites, service, settings }[name] || overview
    )();
  } catch (e) {
    if (currentTab !== name) return;
    app.innerHTML = `<h1>Не удалось загрузить</h1><p>${esc(e.message)}</p><button class="btn secondary" id="retry-tab">Повторить</button>`;
    button("retry-tab", () => tab(name));
  }
}
(async () => {
  try {
    if (selfMode) {
      await self();
    } else {
      const me = await api("/api/me");
      if (!me.is_admin) {
        location.replace("/member");
        return;
      }
      nav.hidden = false;
      nav
        .querySelectorAll("button")
        .forEach((b) => (b.onclick = () => tab(b.dataset.tab)));
      await tab(
        ["overview", "people", "invites", "service", "settings"].includes(
          location.hash.slice(1),
        )
          ? location.hash.slice(1)
          : "overview",
      );
    }
  } catch (e) {
    app.innerHTML = `<h1>Кабинет недоступен</h1><p>${esc(e.message)}</p><p class="muted">Это не означает, что ранее выданный VPN отключён.</p><button class="btn secondary" id="retry-app">Повторить</button>`;
    button("retry-app", () => location.reload());
  }
})();
dialog.addEventListener("close", () => {
  if (!dialog.open) dialog.innerHTML = "";
});
window.addEventListener("pagehide", () => {
  subscription = null;
  dialog.innerHTML = "";
  clearTimeout(refreshTimer);
});

async function operationEvents(id) {
  const events = await api(`/api/cloud/operations/${id}/events`);
  modal(
    `<h2>Журнал операции</h2><small>ID: ${esc(id)}</small>${events.map((e) => `<div class="card"><strong>${esc(phases[e.phase] || e.phase)}</strong><p>${esc({ started: "Начато", completed: "Завершено", waiting: "Ожидаем готовности VPS", failed: "Ошибка" }[e.outcome] || e.outcome)}</p><small>${esc(new Date(e.at).toLocaleString("ru"))} · ${(e.duration_ms / 1000).toFixed(1)} с ${e.http_status ? "· HTTP " + e.http_status : ""}</small>${e.code ? `<p>${esc(e.message || e.code)}</p>` : ""}</div>`).join("") || "<p>Этапы ещё не запускались.</p>"}`,
  );
}

function refreshPeopleLater() {
  refreshTimer = setTimeout(async () => {
    if (currentTab !== "people") return;
    try {
      const version = viewVersion;
      const members = await api("/api/members");
      if (
        version !== viewVersion ||
        currentTab !== "people" ||
        currentPerson !== null
      )
        return;
      memberCache = members;
      drawPeople();
      refreshPeopleLater();
    } catch (e) {
      notice(e.message);
    }
  }, 30000);
}

function groupLabel(m) {
  const g = m.group_membership || { state: "checking" };
  const text =
    {
      inside: "В закрытой группе",
      outside: "Не состоит в группе",
      checking: "Участие в группе проверяется",
      unknown: "Участие в группе неизвестно",
      not_configured: "Группа не настроена",
    }[g.state] || "Участие в группе неизвестно";
  return (
    text +
    (g.checked_at
      ? " · проверка " + new Date(g.checked_at).toLocaleString("ru")
      : "")
  );
}

function bytes(value) {
  const n = Math.max(0, Number(value) || 0),
    fmt = (v) => v.toLocaleString("ru", { maximumFractionDigits: 2 });
  if (n < 1024) return fmt(n) + " Б";
  if (n < 1048576) return fmt(n / 1024) + " КиБ";
  if (n < 1073741824) return fmt(n / 1048576) + " МиБ";
  if (n < 1099511627776) return fmt(n / 1073741824) + " ГиБ";
  return fmt(n / 1099511627776) + " ТиБ";
}

async function loadPersonTraffic(id) {
  try {
    const t = await api(`/api/members/${id}/traffic`);
    const target =
      currentPerson === id ? document.querySelector("#person-traffic") : null;
    if (target) renderTrafficChart(target, t);
  } catch {
    const target =
      currentPerson === id ? document.querySelector("#person-traffic") : null;
    if (target)
      target.textContent =
        "Статистика временно недоступна. Доступ пользователя не изменён.";
  }
}

async function loadSelfTraffic() {
  const target = document.querySelector("#self-traffic");
  button("refresh-self-traffic", loadSelfTraffic);
  try {
    const t = await api("/api/self/traffic");
    renderTrafficChart(target, t);
    button("refresh-self-traffic", loadSelfTraffic);
  } catch {
    target.innerHTML =
      '<p>Статистика временно недоступна. Это не означает, что VPN отключён.</p><button class="btn secondary" id="retry-self-traffic">Повторить</button>';
    button("retry-self-traffic", loadSelfTraffic);
  }
}

function serverCapacityHTML(c) {
  return (
    "<h2>Выходные узлы</h2>" +
    c.nodes
      .map(
        (n) =>
          `<div class="card"><h3>${esc(n.name)}${n.primary ? " · основной" : ""}</h3><p>${!n.enabled ? "Выключен" : n.ready ? "Серверная проверка HTTPS прошла" : "Серверная проверка HTTPS не прошла или выполняется"}</p>${(() => {
            const b = c.budgets.find((b) => b.exit_id === n.id);
            return b
              ? `<p>${b.source === "vultr" ? "Сохранённый объём тарифа (справочно)" : "Бюджет хостинга"}: ${bytes(b.monthly_bytes)}/мес.</p>${b.source === "vultr" ? "<p class=\"muted\">Начисленный трафик и остаток общие для всех выходов Vultr; это не отдельный лимит узла.</p>" : ""}<small>Защитный запас 20%. ${b.source === "vultr" ? (b.error ? "Не удалось обновить данные Vultr" : b.observed_at ? "Данные Vultr: " + esc(new Date(b.observed_at).toLocaleString("ru")) : "Ожидаем данные Vultr") : "Бюджет задан администратором."}</small>`
              : "<small>Бюджет трафика не настроен</small>";
          })()}</div>`,
      )
      .join("")
  );
}

function personTrafficData(t, period, tag = "") {
  const points = (period === "day" ? t.hours : t.day_routes) || [];
  const rawRoutes = (t.routes || [])
    .filter((r) => r.tag && r.tag !== "unknown" && r.tag !== "block")
    .sort((a, b) => a.tag.localeCompare(b.tag));
  const groups = new Map(), tags = new Map();
  for (const route of rawRoutes) {
    const key = route.tag === "direct" ? "direct" : route.group || route.tag;
    if (!groups.has(key)) groups.set(key, { ...route });
    tags.set(route.tag, groups.get(key).tag);
  }
  const routes = [...groups.values()];
  // Map both old and replacement exit points to one displayed direction. Never
  // alter source tags, stored counters or the per-exit quota list.
  const selected = points
    .filter((p) => tags.has(p.tag) && (!tag || tags.get(p.tag) === tag))
    .map((p) => ({ ...p, tag: tags.get(p.tag) }));
  const today = t.today || new Date().toISOString().slice(0, 10),
    month = t.month || today.slice(0, 7);
  const count =
    period === "day"
      ? 24
      : new Date(
          Date.UTC(Number(month.slice(0, 4)), Number(month.slice(5, 7)), 0),
        ).getUTCDate();
  const buckets = Array.from({ length: count }, (_, i) =>
    period === "day"
      ? `${today} ${String(i).padStart(2, "0")}:00`
      : `${month}-${String(i + 1).padStart(2, "0")}`,
  );
  return { routes, selected, buckets, today, month };
}
function quotaDate(value) {
  const date = new Date(value);
  return value && Number.isFinite(date.getTime())
    ? esc(date.toLocaleString("ru", { timeZone: "UTC" })) + " UTC"
    : "уточняется";
}
function quotaKindLabel(item) {
  return (
    { shared: "Общая квота", separate: "Отдельная квота", direct: "Напрямую" }[
      item?.quota_kind || (item?.pool_scope === "vultr" ? "shared" : "")
    ] || ""
  );
}
function trafficQuotasHTML(t) {
  const pool = (t.quota_pools || []).find(
    (p) => p.quota_kind === "shared" || p.scope === "vultr",
  );
  const poolHTML = pool
    ? `<div class="card compact-limits" data-quota-kind="shared"><div class="row"><h2>Общая квота выходов</h2><span class="badge">Общая квота</span></div><small>${esc(pool.period)} · UTC</small><p class="muted">Один личный лимит для отмеченных стран. Смена страны не обновляет остаток.</p><div class="route-row"><span>Личный лимит</span><strong>${bytes(pool.personal_limit_bytes)}</strong></div><div class="route-row"><span>Использовано за месяц</span><strong>${bytes(pool.used_bytes)}</strong></div><div class="route-row"><span>Осталось</span><strong>${pool.state === "unknown" ? "Уточняется" : bytes(pool.remaining_bytes)}</strong></div><p class="${pool.state === "exhausted" ? "bad" : "muted"}">${({ available: "Трафик доступен", exhausted: "Общая квота исчерпана", unknown: "Нет подтверждённого остатка", emergency: "Используется аварийный запас: данные провайдера временно недоступны" })[pool.state] || "Доступность уточняется"}</p><small>${pool.observed_at ? "Последние подтверждённые данные: " + quotaDate(pool.observed_at) : "Ожидаем подтверждённые данные"}<br>Сброс: ${quotaDate(pool.resets_at)}</small></div>`
    : "";
  const limitsHTML = (t.limits || []).map((l) => `<div class="card compact-limits"><h2>${esc(l.name)}</h2><div class="route-row"><span>${l.is_fallback ? "Ручной резерв · общий остаток узла" : "Доступный трафик"}</span><strong>${l.state === "unknown" ? "Уточняется" : bytes(l.remaining_bytes)}</strong></div>${!l.is_fallback && l.period === "month" ? `<p class="muted">Использовано за месяц: ${bytes(l.used_bytes)} · Личный лимит: ${bytes(l.personal_limit_bytes)}<br>Сброс: ${quotaDate(l.resets_at)}. Доступность также ограничена общим остатком узла.</p>` : ""}${l.pending ? '<p class="wait">Применяется переключение</p>' : l.state === "exhausted" ? `<p class="bad">${l.is_fallback ? "Бюджет исчерпан" : "Лимит исчерпан"}</p>` : ""}</div>`).join("");
  return poolHTML + limitsHTML;
}

function renderTrafficChart(target, t, period = "month", tag = "") {
  const colors = [
    "#59bbaa",
    "#94a9f0",
    "#daa862",
    "#d185a7",
    "#98b873",
    "#9d8ecd",
  ];
  const d = personTrafficData(t, period, tag),
    sum = (points) =>
      points.reduce(
        (n, p) =>
          n + (Number(p.uplink_bytes) || 0) + (Number(p.downlink_bytes) || 0),
        0,
      );
  const groups = d.buckets.map((b) => d.selected.filter((p) => p.bucket === b)),
    peak = Math.max(1, ...groups.map(sum)),
    total = sum(d.selected);
  const down = d.selected.reduce(
    (n, p) => n + (Number(p.downlink_bytes) || 0),
    0,
  );
  const routeName = (r) => (r.tag === "direct" ? "Напрямую с bridge" : r.name);
  const routeOption = (r) =>
    routeName(r) + (quotaKindLabel(r) ? " · " + quotaKindLabel(r) : "");
  target.innerHTML = `<div class="card usage-panel"><div class="row"><h2>Трафик по направлениям</h2><div class="period-switch" role="group" aria-label="Период"><button data-period="day" aria-pressed="${period === "day"}">День</button><button data-period="month" aria-pressed="${period === "month"}">Месяц</button></div></div><small>${esc(period === "day" ? d.today : d.month)} · UTC</small><div class="usage-total">${bytes(total)}</div><div class="usage-directions"><span>↓ ${bytes(down)} получено</span><span>↑ ${bytes(total - down)} отправлено</span></div><label>Направление<select id="traffic-route"><option value="">Все направления</option>${d.routes.map((r) => `<option value="${esc(r.tag)}" ${tag === r.tag ? "selected" : ""}>${esc(routeOption(r))}</option>`).join("")}</select></label><div class="chart-scale"><span>${bytes(peak === 1 && total === 0 ? 0 : peak)}</span><span>0</span></div><div class="usage-chart" aria-label="${period === "day" ? "Потребление по часам" : "Потребление по дням"}">${groups
    .map(
      (points, i) =>
        `<button class="chart-column" data-bucket="${i}" aria-label="${esc(d.buckets[i])}: ${bytes(sum(points))}" title="${esc(d.buckets[i])}: ${bytes(sum(points))}">${d.routes
          .map((r, j) => {
            const value = sum(points.filter((p) => p.tag === r.tag));
            return value
              ? `<span style="height:${(value / peak) * 100}%;background:${colors[j % colors.length]}"></span>`
              : "";
          })
          .join("")}</button>`,
    )
    .join(
      "",
    )}</div><div class="chart-axis"><span>${period === "day" ? "00:00" : "1"}</span><span>${period === "day" ? "12:00" : "15"}</span><span>${period === "day" ? "23:00" : d.buckets.length}</span></div><p class="chart-selection" id="chart-selection">${total ? "Выберите столбец для подробностей" : "Трафика за этот период пока нет"}</p><div class="route-summary">${d.routes
    .filter((r) => !tag || r.tag === tag)
    .map((r) => {
      const j = d.routes.indexOf(r),
        value = sum(d.selected.filter((p) => p.tag === r.tag));
      return `<div class="route-row"><span><i style="background:${colors[j % colors.length]}"></i>${esc(routeName(r))}${quotaKindLabel(r) ? ` <span class="badge">${esc(quotaKindLabel(r))}</span>` : ""}</span><strong>${bytes(value)}</strong><small>${total ? Math.round((value / total) * 100) : 0}%</small></div>`;
    })
    .join(
      "",
    )}</div></div>${trafficQuotasHTML(t)}`;
  target
    .querySelectorAll("[data-period]")
    .forEach(
      (el) =>
        (el.onclick = () =>
          renderTrafficChart(target, t, el.dataset.period, tag)),
    );
  target.querySelector("#traffic-route").onchange = (e) =>
    renderTrafficChart(target, t, period, e.target.value);
  target.querySelectorAll("[data-bucket]").forEach(
    (el) =>
      (el.onclick = () => {
        const i = Number(el.dataset.bucket),
          points = groups[i];
        target.querySelector("#chart-selection").textContent =
          d.buckets[i] +
          " · " +
          bytes(sum(points)) +
          " · " +
          d.routes
            .filter((r) => sum(points.filter((p) => p.tag === r.tag)) > 0)
            .map(
              (r) =>
                routeName(r) +
                ": " +
                bytes(sum(points.filter((p) => p.tag === r.tag))),
            )
            .join(" · ");
      }),
  );
}

async function loadCloudAccount() {
  const target = document.querySelector("#cloud-account");
  if (!target) return;
  try {
    const a = await api("/api/cloud/account");
    if (document.querySelector("#cloud-account") !== target) return;
    const money = (n) =>
      Number(n).toLocaleString("ru", { style: "currency", currency: "USD" });
    target.innerHTML = `<div class="card"><h2>Баланс Vultr</h2><div class="usage-total">${esc(money(a.balance))}</div><p>Начислено за месяц: <strong>${esc(money(a.pending_charges))}</strong></p><small>Данные аккаунта · ${esc(new Date(a.observed_at).toLocaleString("ru"))}</small><a class="link" href="https://my.vultr.com/billing/" target="_blank" rel="noopener noreferrer">Открыть биллинг Vultr ↗</a></div>`;
  } catch {
    if (document.querySelector("#cloud-account") === target)
      target.innerHTML =
        '<p class="muted">Баланс Vultr временно недоступен</p>';
  }
}

function applicationLabel(a) {
  return (
    {
      applied: "Применено на сервере",
      applying: "Применяется на сервере",
      error: "Ошибка применения · повторяем автоматически",
    }[a?.state] || "Маршрут ещё не подтверждён"
  );
}
function routeReasonLabel(reason) {
  return (
    {
      monthly_user_limit_exhausted: "Личный лимит этого выхода исчерпан",
      exit_budget_exhausted: "Общий бюджет узла исчерпан",
      provider_unavailable: "Нет подтверждённого остатка трафика провайдера",
      provider_emergency_exhausted: "Аварийный запас трафика исчерпан",
      runtime_authorization_expired: "Срок автономной работы истёк",
      quota_pending: "Ожидаем расчёт лимита",
      exit_unavailable: "Выбранный выход недоступен или восстанавливается",
      no_available_exit: "Нет допустимого выхода · VPN-трафик заблокирован",
    }[reason] || "Выбранный маршрут временно недоступен"
  );
}
function serverBillingLabel(o) {
  return o.charged
    ? "Оплата продолжается"
    : o.state === "unknown"
      ? "Наличие оплачиваемого ресурса уточняется"
      : "Слот зарезервирован; покупка ещё не выполнена";
}
function serverStateLabel(o, capacity) {
  if (o.state === "unknown") return "Результат создания проверяется";
  if (o.state === "failed") return "Ошибка · требуется действие";
  if (o.state === "ready") {
    const node = capacity?.nodes?.find((n) => n.id === o.exit_id);
    return !node
      ? "Сервер создан · статус туннеля уточняется"
      : node.ready
        ? "Серверная проверка HTTPS прошла"
        : "Сервер создан · туннель недоступен";
  }
  return phases[o.phase] || "Создание сервера";
}
