"use strict";

function editConfigName(user) {
  modal(
    `<h2>${user ? "Переименовать конфиг" : "Новый ручной доступ"}</h2><label for="config-name">Имя</label><input id="config-name" maxlength="200" value="${esc(user?.name || "")}" autocomplete="off"><p class="muted">${user ? "Название помогает найти нужный ключ." : "Создаётся VLESS-конфиг без привязки к Telegram. Для личного кабинета используйте приглашение."}</p><button class="btn" id="save-config">${user ? "Сохранить" : "Создать"}</button>`,
  );
  button("save-config", async () => {
    const name = document.querySelector("#config-name").value.trim();
    if (!name) throw new Error("Введите имя");
    const result = await api(
      user ? `/api/users/${encodeURIComponent(user.uuid)}` : "/api/users",
      user ? "PATCH" : "POST",
      user ? { name } : { name, kind: "vless" },
    );
    dialog.close();
    if (user) await configDetail({ ...user, name });
    else await configDetail(result.user || result.User || result);
  });
}
function configControls(user) {
  const vless = (user.kind || "vless") === "vless";
  return `<div class="card"><div class="row wrap"><h2>Управление конфигом</h2><span class="badge ${user.is_active ? "good" : "bad"}">${user.is_active ? "Доступ разрешён" : "Доступ отключён"}</span></div><button class="btn secondary" id="rename-config">Переименовать</button>${vless && user.is_active ? '<button class="btn" id="export-config">Конфигурация и QR-код</button><button class="btn secondary" id="issue-config-sub">Выдать / заменить подписку Happ</button><button class="btn secondary" id="revoke-config-sub">Отозвать подписку</button>' : ""}<details><summary>Изменить доступ</summary>${user.is_active ? `${vless ? '<button class="btn secondary" id="rotate-config">Перевыпустить ключ</button>' : ""}<button class="btn danger" id="disable-config">Отключить конфиг</button>` : `${vless ? '<button class="btn" id="enable-config">Включить конфиг</button>' : "<p>Архивный тип доступа. Доступно только чтение истории и удаление.</p>"}<button class="btn danger" id="purge-config">Удалить навсегда</button>`}</details></div>`;
}
function bindConfigControls(user) {
  const path = "/api/users/" + encodeURIComponent(user.uuid);
  button("rename-config", () => editConfigName(user));
  button("export-config", () => exportConfig(user));
  button("disable-config", () =>
    confirm(
      "Отключить конфиг?",
      "Устройства с этим ключом перестанут подключаться. История останется.",
      "Отключить",
      async () => {
        await api(path, "DELETE");
        await configDetail({ ...user, is_active: false });
      },
    ),
  );
  button("enable-config", async () => {
    await api(path + "/enable", "POST");
    await configDetail({ ...user, is_active: true });
  });
  button("rotate-config", () =>
    confirm(
      "Перевыпустить ключ?",
      "Старый ключ перестанет работать. Все устройства потребуется настроить заново.",
      "Перевыпустить",
      async () => {
        const result = await api(path + "/rotate", "POST");
        const uuid = result.uuid || result.UUID;
        if (!uuid) throw new Error("Сервер не вернул новый ключ");
        await configDetail({ ...user, uuid });
        notice("Ключ заменён. Импортируйте новый конфиг на устройствах.");
      },
    ),
  );
  button("purge-config", () => {
    modal(
      `<h2>Удалить конфиг навсегда?</h2><p>История доступа и наблюдений будет удалена. Общий расход серверов сохранится и не вернёт потраченную квоту. Для подтверждения введите «УДАЛИТЬ».</p><label for="purge-word">Подтверждение</label><input id="purge-word" autocomplete="off"><button class="btn danger" id="purge-confirm">Удалить навсегда</button>`,
    );
    button("purge-confirm", async () => {
      if (document.querySelector("#purge-word").value !== "УДАЛИТЬ")
        throw new Error("Введите УДАЛИТЬ для подтверждения");
      await api(path + "/purge", "DELETE");
      dialog.close();
      await manualUsers();
    });
  });
  button("issue-config-sub", () =>
    confirm(
      "Выдать новую подписку?",
      "Прежняя ссылка подписки перестанет обновляться. Уже скачанные VLESS-профили сохранятся.",
      "Выдать подписку",
      async () => {
        const result = await api(path + "/subscription", "POST");
        const importURL = subscriptionImportURL(result.url);
        modal(
          `<h2>Подписка Happ</h2><p class="muted">Не передавайте ссылку посторонним.</p><button class="btn" id="open-config-happ">Открыть в Happ</button><button class="btn secondary" id="copy-config-sub">Скопировать подписку</button><p class="secret">${esc(result.url)}</p>`,
        );
        button("open-config-happ", () => openExternal(importURL));
        button("copy-config-sub", () => copy(result.url));
      },
    ),
  );
  button("revoke-config-sub", () =>
    confirm(
      "Отозвать подписку?",
      "Ссылка перестанет работать. Скачанные конфиги останутся действительными; для их блокировки отключите доступ.",
      "Отозвать",
      async () => {
        await api(path + "/subscription", "DELETE");
        notice("Подписка отозвана");
      },
    ),
  );
}
function subscriptionImportURL(raw) {
  const subscription = new URL(raw);
  if (
    subscription.protocol !== "https:" ||
    !/^\/sub\/[A-Za-z0-9_-]{43}$/.test(subscription.pathname)
  )
    throw new Error("Некорректная ссылка подписки");
  const result = new URL("/happ", subscription.origin);
  result.hash = subscription.pathname.split("/").pop();
  return result.href;
}
async function exportConfig(user) {
  const version = viewVersion;
  const data = await api(
    "/api/users/" + encodeURIComponent(user.uuid) + "/config",
  );
  if (version !== viewVersion) return;
  const profiles = data.profiles?.length
    ? data.profiles
    : [{ name: "Основной", vless_uri: data.vless_uri || data.VLESSURI }];
  modal(
    `<h2>Конфигурация VLESS</h2><label for="export-profile">Профиль</label><select id="export-profile">${profiles.map((p, i) => `<option value="${i}">${esc(p.name || p.id || "Профиль")}</option>`).join("")}</select><div id="config-qr" class="qr-code"></div><p id="config-uri" class="secret"></p><button class="btn" id="copy-config-uri">Скопировать VLESS URI</button>`,
  );
  function render() {
    const uri =
      profiles[Number(document.querySelector("#export-profile").value) || 0]
        ?.vless_uri || "";
    document.querySelector("#config-uri").textContent =
      uri || "Профиль недоступен";
    const target = document.querySelector("#config-qr");
    target.innerHTML = "";
    if (uri) {
      try {
        const qr = qrcode(0, "M");
        qr.addData(uri);
        qr.make();
        target.innerHTML = qr.createImgTag(4, 16, "QR-код конфигурации VLESS");
      } catch {
        target.textContent = "QR-код недоступен. Скопируйте ссылку ниже.";
      }
    }
    const copyButton = document.querySelector("#copy-config-uri");
    copyButton.disabled = !uri;
    button("copy-config-uri", () => copy(uri));
  }
  document.querySelector("#export-profile").onchange = render;
  render();
}
async function loadConfigMonth(user, version) {
  const target = document.querySelector("#config-monthly"),
    month = document.querySelector("#config-month").value;
  if (!/^\d{4}-\d{2}$/.test(month)) return;
  target.textContent = "Загружаем статистику…";
  try {
    const d = await api(
      `/api/users/${encodeURIComponent(user.uuid)}/traffic?month=${month}`,
    );
    if (
      version !== viewVersion ||
      document.querySelector("#config-month").value !== month
    )
      return;
    const up = Number(d.UplinkBytes ?? d.uplink_bytes) || 0,
      down = Number(d.DownlinkBytes ?? d.downlink_bytes) || 0;
    target.innerHTML = barsHTML(
      [
        { label: "Отправлено", value: up },
        { label: "Получено", value: down },
        { label: "Всего", value: up + down },
      ],
      "Отправленный и полученный трафик за месяц",
    );
    bindBars(target);
  } catch {
    if (version !== viewVersion) return;
    target.innerHTML = panelError("Трафик за месяц", "retry-config-month");
    button("retry-config-month", () => loadConfigMonth(user, version));
  }
}
async function loadConfigSignals(user, version) {
  const target = document.querySelector("#config-signals");
  try {
    const data = await api(`/api/users/${encodeURIComponent(user.uuid)}/leak`);
    if (version !== viewVersion) return;
    target.innerHTML = `<div class="card"><h2>Подозрительная активность</h2><p class="muted">Наблюдения по IP не означают число устройств. Автоматического отключения нет.</p><div class="metrics">${metric("IP за минуту", data.concurrent_ips, `Алерт при > ${data.concurrent_threshold ?? 5}`)}${metric("IP за 24 часа", data.unique_ips_24h, `Алерт при > ${data.unique_ips_24h_threshold ?? 10}`)}</div>${data.suspicious ? '<p class="badge wait">Порог активности превышен</p>' : '<p class="badge good">Порог активности не превышен</p>'}${(data.signals || []).map((s) => `<div class="event"><strong>${esc(s.Kind || s.kind)}</strong><span> · Оценка ${esc(s.Score ?? s.score ?? "—")}</span><small> · ${esc(dateLabel(s.CreatedAt || s.created_at))}</small></div>`).join("")}</div>`;
  } catch {
    if (version !== viewVersion) return;
    target.innerHTML = panelError(
      "Наблюдения активности",
      "retry-config-signals",
    );
    button("retry-config-signals", () => loadConfigSignals(user, version));
  }
}
