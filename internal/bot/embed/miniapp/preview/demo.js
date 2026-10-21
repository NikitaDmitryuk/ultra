"use strict";
// This preview has no backend transport: every action stays in page memory.
(() => {
  const theme = new URLSearchParams(location.search).get("theme");
  if (["light", "dark"].includes(theme) && document.documentElement)
    document.documentElement.dataset.theme = theme;
  const now = new Date().toISOString();
  const people = [
    {
      uuid: "demo-1",
      telegram_id: 100001,
      name: "Алексей",
      active: true,
      pending: false,
      source: "group",
      enrolled_at: now,
    },
    {
      uuid: "demo-2",
      telegram_id: 100002,
      name: "Мария",
      active: true,
      pending: true,
      source: "invite",
      enrolled_at: now,
    },
    {
      uuid: "demo-3",
      telegram_id: 100003,
      name: "Дмитрий",
      active: false,
      pending: false,
      source: "invite",
      enrolled_at: now,
    },
  ];
  let group = {
    chat_id: -100123456,
    title: "Друзья Ultra",
    enabled: true,
    url: "https://example.invalid/demo-group",
  };
  const invites = [
    {
      id: 1,
      recipient: 100004,
      recipient_name: "Анна",
      expires_at: new Date(Date.now() + 5 * 86400000).toISOString(),
      created_at: now,
    },
  ];
  const region = { id: "fra", city: "Франкфурт", country: "DE" },
    plan = { id: "vc2-1c-1gb", bandwidth: 1024 },
    price = { monthly_cost: 5, hourly_cost: 0.007 };
  const ops = [
    {
      id: "demo-fra",
      instance_id: "demo-instance",
      exit_id: "fra",
      offer: { region, plan, price },
      state: "ready",
      phase: "ready",
      charged: true,
    },
  ];
  const traffic = {
    month: now.slice(0, 7),
    uplink_bytes: 2 * 1073741824,
    downlink_bytes: 24 * 1073741824,
    routes: [
      {
        name: "Амстердам",
        uplink_bytes: 1073741824,
        downlink_bytes: 20 * 1073741824,
      },
      {
        name: "Напрямую с bridge",
        uplink_bytes: 1073741824,
        downlink_bytes: 4 * 1073741824,
      },
    ],
    days: [
      {
        day: now.slice(0, 10),
        uplink_bytes: 2 * 1073741824,
        downlink_bytes: 24 * 1073741824,
      },
    ],
    quota_pools: [{
      scope: "vultr",
      period: now.slice(0, 7),
      personal_limit_bytes: 100 * 1073741824,
      used_bytes: 21 * 1073741824,
      remaining_bytes: 79 * 1073741824,
      observed_at: now,
      state: "available",
      resets_at: new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth() + 1, 1)).toISOString(),
    }],
    limits: [{
      name: "Резервный выход",
      is_fallback: true,
      state: "available",
      remaining_bytes: 10 * 1073741824,
    }],
  };
  traffic.today = now.slice(0, 10);
  traffic.routes[0].tag = "to-exit-ams";
  traffic.routes[0].pool_scope = "vultr";
  traffic.routes[1].tag = "direct";
  traffic.day_routes = Array.from(
    { length: Math.min(8, Number(now.slice(8, 10))) },
    (_, i) =>
      traffic.routes.map((r, j) => ({
        bucket: now.slice(0, 8) + String(i + 1).padStart(2, "0"),
        tag: r.tag,
        uplink_bytes: (i + 1) * 4000000,
        downlink_bytes: (j === 0 ? 8 : 2) * (i + 1) * 50000000,
      })),
  ).flat();
  traffic.hours = Array.from({ length: 24 }, (_, i) =>
    traffic.routes.map((r, j) => ({
      bucket: now.slice(0, 10) + " " + String(i).padStart(2, "0") + ":00",
      tag: r.tag,
      uplink_bytes: 1000000 * (i % 3),
      downlink_bytes: (j === 0 ? 6 : 2) * (i % 5) * 20000000,
    })),
  ).flat();
  people[0].last_traffic_at = now;
  people[0].group_membership = { state: "inside", checked_at: now };
  let preferred = null;
  const exits = [
    { id: "ams", display_name: "Нидерланды · Амстердам", reachable: true },
    { id: "fra", display_name: "Германия · Франкфурт", reachable: true },
  ];
  const state = new URLSearchParams(location.search).get("state");
  if (state === "disabled") people[0].active = false;
  if (state === "pending") people[0].pending = true;
  window.fetch = async (path, options = {}) => {
    let body = {};
    try {
      body = JSON.parse(options.body || "{}") || {};
    } catch {}
    let value,
      status = 200;
    if (path === "/api/me")
      value = { is_admin: true, telegram_id: 100001, name: "Алексей" };
    else if (path === "/api/self")
      value = {
        registered: state !== "new",
        is_admin: true,
        member: people[0],
      };
    else if (path === "/api/members/traffic")
      value = { ...traffic, limits: [], quota_pools: [] };
    else if (
      path === "/api/self/traffic" ||
      /^\/api\/members\/\d+\/traffic$/.test(path)
    )
      value = traffic;
    else if (path === "/api/self/subscription")
      value = {
        url: "https://example.invalid/demo-subscription",
        import_url: "https://example.invalid/demo-import",
      };
    else if (path === "/api/self/exits")
      value = {
        application: { state: "applied" },
        exits,
        selected_exit_id: null,
        effective_exit_id: "ams",
        profiles: exits.map((e) => ({
          name: e.display_name,
          effective_exit_id: e.id,
        })),
      };
    else if (path === "/api/self/exit-selection") {
      preferred = body.exit_id;
      value = {};
    } else if (path === "/api/members") value = people;
    else if (/^\/api\/members\/\d+\/action$/.test(path)) {
      const person = people.find(
        (p) => String(p.telegram_id) === path.split("/")[3],
      );
      if (person) {
        if (body.action === "reset") person.uuid += "-reset";
        else person.active = body.action === "enable";
        person.pending = false;
        value = person;
      } else status = 404;
    } else if (path === "/api/enrollment/group") {
      if (options.method === "PUT") group = { ...group, ...body };
      value = group;
    } else if (path === "/api/enrollment/invites") {
      if (options.method === "POST") {
        invites.unshift({
          id: Date.now(),
          recipient: body.recipient,
          expires_at: new Date(Date.now() + 7 * 86400000).toISOString(),
        });
        value = { url: "https://example.invalid/demo-invite" };
      } else value = invites;
    } else if (
      path.includes("/api/enrollment/invites/") &&
      path.endsWith("/cancel")
    ) {
      const i = invites.find((i) => String(i.id) === path.split("/")[4]);
      if (i) i.cancelled_at = now;
      value = {};
    } else if (path === "/api/enrollment/picker") {
      alert(
        "В рабочем боте здесь появится штатный выбор Telegram-аккаунта. Макет не отправляет сообщения.",
      );
      value = {};
    } else if (path === "/api/enrollment/group-picker") {
      value = {};
    } else if (path === "/api/stats")
      value = { total_users: 8, total_bytes_month: 186 * 1073741824 };
    else if (path === "/api/stats/history?months=12")
      value = Array.from({ length: 8 }, (_, i) => {
        const d = new Date();
        d.setUTCMonth(d.getUTCMonth() - 7 + i);
        return {
          Year: d.getUTCFullYear(),
          Month: d.getUTCMonth() + 1,
          TotalBytes: (40 + [12, 33, 20, 71, 56, 99, 81, 146][i]) * 1073741824,
        };
      });
    else if (path === "/api/users" && options.method === "POST")
      value = {
        user: {
          uuid: "demo-created",
          name: body.name,
          kind: "vless",
          is_active: true,
        },
      };
    else if (path === "/api/users")
      value = people.map((p, i) => ({
        uuid: p.uuid,
        name: p.name,
        is_active: p.active,
        kind: "vless",
        total_bytes: (56 - i * 17) * 1073741824,
        uplink_bytes: 3 * 1073741824,
        downlink_bytes: (53 - i * 17) * 1073741824,
      }));
    else if (/^\/api\/users\/[^/]+$/.test(path) && options.method === "PATCH")
      value = { user: { name: body.name } };
    else if (path.startsWith("/api/users/") && path.endsWith("/rotate"))
      value = { uuid: "demo-rotated" };
    else if (path.startsWith("/api/users/") && path.endsWith("/config"))
      value = {
        profiles: [
          {
            name: "Автоматически",
            vless_uri:
              "vless://00000000-0000-0000-0000-000000000001@example.invalid:443?security=tls#Ultra-demo",
          },
        ],
      };
    else if (path.startsWith("/api/users/") && path.endsWith("/subscription"))
      value = { url: "https://example.invalid/sub/" + "A".repeat(43) };
    else if (path.startsWith("/api/users/") && path.includes("/traffic?month="))
      value = { UplinkBytes: 3000000000, DownlinkBytes: 53000000000 };
    else if (path.startsWith("/api/users/") && path.endsWith("/leak"))
      value = {
        concurrent_ips: 2,
        unique_ips_24h: 4,
        suspicious: false,
        signals: [],
      };
    else if (
      path.startsWith("/api/users/") &&
      (options.method === "DELETE" || path.endsWith("/enable"))
    )
      value = {};
    else if (path.includes("/traffic/timeline?window="))
      value = {
        points: Array.from({ length: 24 }, (_, i) => ({
          BucketStart: new Date(Date.now() - (24 - i) * 3600000).toISOString(),
          TotalBytes: (1 + (i % 6)) * 24000000,
        })),
      };
    else if (path === "/api/health")
      value = {
        checked_at: now,
        bridge: { internet_ok: true },
        exit: { name: "Амстердам", reachable: true, internet_ok: true },
        exits: exits.map((e, i) => ({
          id: e.id,
          name: e.display_name,
          active: i === 0,
          reachable: true,
          internet_ok: true,
          tunnel_latency_ms: 35 + i * 12,
        })),
        public_ingresses: [
          { id: "primary", ready: true, phase: "server_path_ready" },
        ],
      };
    else if (path === "/api/alerts/recent?limit=10")
      value = [
        {
          type: "exit_up",
          created_at: now,
          payload: { text: "Франкфурт снова доступен", severity: "info" },
        },
      ];
    else if (path === "/api/admins")
      value = [
        { TelegramID: 100001, TelegramName: "Алексей" },
        { TelegramID: 100008, TelegramName: "Екатерина" },
      ];
    else if (path === "/api/admin/invite")
      value = { token: "demo-admin-token" };
    else if (path === "/api/alerts/test" || path.endsWith("/remove"))
      value = {};
    else if (path === "/api/cloud/account")
      value = { balance: 12.5, pending_charges: 1.25, observed_at: now };
    else if (path === "/api/cloud/quotas")
      value = {
        nodes: exits.map((e) => ({
          id: e.id,
          name: e.display_name,
          enabled: true,
          ready: e.reachable,
          primary: e.id === "ams",
        })),
        budgets: [],
      };
    else if (path === "/api/cloud/operations") value = ops;
    else if (path === "/api/cloud/replicas")
      value = [{ id: "bridge", name: "Bridge PostgreSQL standby", source: "primary", state: "streaming", replay_lag_bytes: 0, checked_at: new Date().toISOString() }];
    else if (path === "/api/cloud/catalog")
      value = {
        regions: [
          region,
          { id: "ams", city: "Амстердам", country: "NL" },
          { id: "waw", city: "Варшава", country: "PL" },
        ],
        plans: [plan],
      };
    else if (path === "/api/cloud/offers")
      value = {
        id: "demo-offer",
        region:
          body.region === "fra"
            ? region
            : {
                id: body.region,
                city: body.region === "ams" ? "Амстердам" : "Варшава",
              },
        plan,
        price,
      };
    else if (path.endsWith("/events"))
      value = [
        { phase: "verify", outcome: "completed", at: now, duration_ms: 1500 },
      ];
    else if (path.endsWith("/confirm")) {
      alert("Это макет: VPS не покупается и реальные средства не списываются.");
      value = {};
    } else if (
      path.startsWith("/api/cloud/operations/") &&
      path.endsWith("/action")
    ) {
      const op = ops.find((o) => o.id === path.split("/")[4]);
      if (op) {
        op.state = body.action === "delete" ? "deleted" : "pending";
        op.phase = body.action === "delete" ? "cleanup" : "verify";
      }
      value = {};
    } else {
      status = 503;
      value = {};
    }
    return {
      ok: status === 200,
      status,
      json: async () => JSON.parse(JSON.stringify(value || {})),
    };
  };
  window.Telegram = {
    WebApp: {
      ready() {},
      expand() {},
      initData: "",
      openLink() {
        alert(
          "В рабочем кабинете эта кнопка откроет импорт вашей подписки в Happ. В макете ключей VPN нет.",
        );
      },
      close() {},
    },
  };
  document.addEventListener("click", (event) => {
    const link = event.target.closest("a");
    if (!link) return;
    const href = link.getAttribute("href");
    if (href === "/") link.href = "admin.html";
    else if (href === "/member") link.href = "member.html";
    else if (href === "/#invites") link.href = "admin.html#invites";
  });
})();
