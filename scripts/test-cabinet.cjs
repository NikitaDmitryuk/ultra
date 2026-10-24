const { test } = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const dashboard = fs.readFileSync(
  require("node:path").join(
    __dirname,
    "../internal/bot/embed/miniapp/dashboard.js",
  ),
  "utf8",
);
const configs = fs.readFileSync(
  require("node:path").join(
    __dirname,
    "../internal/bot/embed/miniapp/configs.js",
  ),
  "utf8",
);
const source =
  configs +
  "\n" +
  dashboard +
  "\n" +
  fs.readFileSync(
    require("node:path").join(
      __dirname,
      "../internal/bot/embed/miniapp/cabinet.js",
    ),
    "utf8",
  );
const flush = () => new Promise((resolve) => setImmediate(resolve));
function page(self, responses) {
  const elements = new Map(),
    calls = [],
    copied = [],
    opened = [],
    timers = [];
  function el(id) {
    if (!elements.has(id))
      elements.set(id, {
        insertAdjacentHTML(position, html) {
          this.innerHTML += html;
        },
        innerHTML: "",
        value: "",
        dataset: {},
        classList: { toggle() {} },
        setAttribute() {},
        focus() { this.focused = true; },
        querySelector(selector) {
          return el(selector);
        },
        querySelectorAll() {
          return [];
        },
        addEventListener() {},
        async click() {
          if (this.disabled || typeof this.onclick !== "function") return;
          return this.onclick({ currentTarget: this, target: this });
        },
        showModal() {
          this.open = true;
        },
        close() {
          this.open = false;
        },
      });
    return elements.get(id);
  }
  const context = vm.createContext({
    URL,
    Date,
    Number,
    String,
    Error,
    Promise,
    JSON,
    location: {
      pathname: self ? "/member" : "/",
      hash: "",
      replace() {},
      reload() {},
    },
    window: {
      Telegram: {
        WebApp: {
          initData: "signed-test-session",
          ready() {},
          expand() {},
          openLink(url) {
            opened.push(url);
          },
        },
      },
      addEventListener() {},
      open() {
        throw new Error("unexpected fallback");
      },
    },
    document: {
      activeElement: null,
      querySelector: el,
      getElementById: (id) => el("#" + id),
      querySelectorAll() {
        return [];
      },
    },
    navigator: {
      clipboard: {
        async writeText(text) {
          copied.push(text);
        },
      },
    },
    setTimeout(callback, delay) {
      timers.push({ callback, delay, cancelled: false });
      return timers.length;
    },
    clearTimeout(id) { if (timers[id - 1]) timers[id - 1].cancelled = true; },
    fetch: async (path, options) => {
      calls.push({ path, options });
      if (!(path in responses)) throw new Error("unexpected request " + path);
      if (responses[path] instanceof Error) throw responses[path];
      return { ok: true, status: 200, json: async () => responses[path] };
    },
  });
  vm.runInContext(source, context);
  return { context, el, calls, copied, opened, responses, timers };
}
test("personal cabinet reuses subscription and opens HTTPS import without admin APIs", async () => {
  const p = page(true, {
    "/api/self": {
      registered: true,
      is_admin: true,
      member: { uuid: "owner", active: true, pending: false },
    },
    "/api/self/exits": { exits: [], profiles: [] },
    "/api/self/subscription": {
      url: "https://vpn.example/sub/test",
      import_url: "https://vpn.example/happ#test",
    },
  });
  await flush();
  await p.el("#copy-sub").onclick();
  await p.el("#copy-sub").onclick();
  await p.el("#connect").onclick();
  assert.equal(
    p.calls.filter((c) => c.path === "/api/self/subscription").length,
    1,
  );
  assert.deepEqual(p.copied, [
    "https://vpn.example/sub/test",
    "https://vpn.example/sub/test",
  ]);
  assert.deepEqual(p.opened, ["https://vpn.example/happ#test"]);
  assert.ok(p.el("#app").innerHTML.includes("Доступ и устройства"));
  assert.ok(
    p.el("#app").innerHTML.includes(
      "Состояние подписки, маршруты и расход трафика",
    ),
  );
  assert.ok(!p.el("#app").innerHTML.includes("Ваш интернет"));
  assert.equal(p.el("#switch").hidden, false);
  assert.ok(p.calls.every((c) => c.path.startsWith("/api/self")));
  assert.ok(p.calls.every((c) => c.options.cache === "no-store"));
});

test("subscription recovery tells the user the previous URL was invalidated", async () => {
  const p = page(true, {
    "/api/self": {
      registered: true,
      member: { uuid: "owner", active: true, pending: false },
    },
    "/api/self/exits": { exits: [], profiles: [] },
    "/api/self/subscription": {
      url: "https://vpn.example/sub/new",
      import_url: "https://vpn.example/happ#new",
      rotated: true,
    },
  });
  await flush();
  await p.el("#copy-sub").onclick();
  assert.deepEqual(p.copied, ["https://vpn.example/sub/new"]);
  assert.match(p.el("#notice").textContent, /Старая ссылка подписки отозвана/);
});
test("disabled access cannot issue a subscription", async () => {
  const p = page(true, {
    "/api/self": {
      registered: true,
      is_admin: false,
      member: { uuid: "owner", active: false, pending: false },
    },
  });
  await flush();
  assert.ok(p.el("#app").innerHTML.includes("Доступ приостановлен"));
  assert.ok(!p.el("#app").innerHTML.includes('id="connect"'));
  assert.ok(
    p.calls.every((c) => ["/api/self", "/api/self/traffic"].includes(c.path)),
  );
});
test("member access control opens confirmation on the first click", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members/42/traffic": { months: [] },
    "/api/members/42/action": {
      telegram_id: 42,
      uuid: "member-key",
      active: false,
      pending: false,
      name: "Member",
    },
    "/api/members/42/leak": {},
  });
  await flush();
  p.context.member = {
    telegram_id: 42,
    uuid: "member-key",
    active: true,
    pending: false,
    name: "Member",
  };
  vm.runInContext("person(member)", p.context);

  await p.el("#toggle-access").click();
  assert.equal(p.el("#dialog").open, true);
  assert.equal(
    p.calls.some((call) => call.path === "/api/members/42/action"),
    false,
  );

  await p.el("#confirm-action").click();
  const actions = p.calls.filter(
    (call) => call.path === "/api/members/42/action",
  );
  assert.equal(actions.length, 1);
  assert.equal(actions[0].options.method, "POST");
  assert.deepEqual(JSON.parse(actions[0].options.body), {
    action: "disable",
    expected_uuid: "member-key",
  });
});
test("Vultr displays server DTO price and replica state", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [],
    "/api/cloud/operations": [
      {
        id: "op",
        offer: {
          region: { city: "Frankfurt" },
          plan: { id: "vc2-1c-1gb" },
          price: { monthly_cost: 5, hourly_cost: 0.007 },
        },
        state: "ready",
        phase: "ready",
        charged: true,
        instance_id: "instance",
      },
    ],
    "/api/cloud/replicas": [
      {
        id: "bridge",
        name: "Bridge PostgreSQL standby",
        state: "streaming",
        source: "primary",
        replay_lag_bytes: 0,
        checked_at: "2026-01-01T12:00:00Z",
      },
    ],
  });
  await flush();
  await vm.runInContext("service()", p.context);
  assert.ok(p.el("#app").innerHTML.includes("$5/месяц"));
  assert.ok(!p.el("#app").innerHTML.includes("$undefined"));
  assert.ok(p.el("#app").innerHTML.includes("Копия обновляется"));
  assert.ok(!p.el("#app").innerHTML.includes("Добавить узел вручную"));
});

test("deleted Vultr exits are removed from server list even if quota DTO is stale", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [],
    "/api/cloud/operations": [
      { id: "old-op", exit_id: "old-exit", state: "deleted" },
    ],
    "/api/cloud/quotas": {
      nodes: [
        { id: "old-exit", name: "Удалённый сервер", enabled: false },
        { id: "active-exit", name: "Действующий сервер", enabled: true },
      ],
      budgets: [],
    },
    "/api/cloud/replicas": [],
  });
  await flush();
  await vm.runInContext("service()", p.context);
  const html = p.el("#app").innerHTML;
  assert.ok(!html.includes("Удалённый сервер"));
  assert.ok(html.includes("Действующий сервер"));
});

test("Vultr status polling updates the existing card without replacing its price", async () => {
  const op = {
    id: "op",
    offer: {
      region: { city: "Frankfurt" },
      plan: { id: "vc2-1c-1gb" },
      price: { monthly_cost: 5, hourly_cost: 0.007 },
    },
    state: "pending",
    phase: "create",
    charged: false,
  };
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [],
    "/api/cloud/operations": [op],
    "/api/cloud/quotas": { nodes: [], budgets: [] },
    "/api/cloud/replicas": [],
  });
  await flush();
  vm.runInContext('currentTab = "service"', p.context);
  await vm.runInContext("service()", p.context);
  const html = p.el("#app").innerHTML;
  const status = { className: "", textContent: "" };
  let detailsHTML = "";
  let detailsWrites = 0;
  const details = {
    get innerHTML() {
      return detailsHTML;
    },
    set innerHTML(value) {
      detailsWrites++;
      detailsHTML = value;
    },
  };
  const card = {
    dataset: { opCard: "op" },
    hidden: false,
    querySelector(selector) {
      return selector === "[data-op-status]" ? status : details;
    },
  };
  p.el("#cloud-operations").querySelectorAll = (selector) =>
    selector === "[data-op-card]" ? [card] : [];
  p.responses["/api/cloud/operations"] = [
    { ...op, state: "unknown", phase: "verify", charged: true },
  ];

  await vm.runInContext(
    "refreshOperationCards(viewVersion)",
    p.context,
  );

  assert.equal(p.el("#app").innerHTML, html);
  assert.ok(html.includes("$5/месяц"));
  assert.equal(status.textContent, "Результат создания проверяется");
  assert.match(details.innerHTML, /Оплата продолжается/);
  await vm.runInContext("refreshOperationCards(viewVersion)", p.context);
  assert.equal(detailsWrites, 1);
});

test("Vultr polling inserts new cards and manual refresh preserves existing cards", async () => {
  const makeOp = (id, state = "pending") => ({
    id,
    offer: {
      region: { city: "Frankfurt" },
      plan: { id: "vc2-1c-1gb" },
      price: { monthly_cost: 5, hourly_cost: 0.007 },
    },
    state,
    exit_id: id === "delete" ? "removed-exit" : undefined,
    phase: "create",
    charged: false,
  });
  const keepStatus = { className: "", textContent: "Создание сервера" };
  const keepDetails = { innerHTML: "" };
  const keepPrice = { textContent: "$5/месяц" };
  const openLog = { open: true, textContent: "Existing event" };
  const keepCard = {
    dataset: { opCard: "keep" },
    hidden: false,
    price: keepPrice,
    log: openLog,
    querySelector(selector) {
      return selector === "[data-op-status]" ? keepStatus : keepDetails;
    },
    remove() {
      this.removed = true;
    },
  };
  const deletedCard = {
    dataset: { opCard: "delete" },
    remove() {
      this.removed = true;
    },
  };
  const addedCards = [];
  const operations = {
    innerHTML: "",
    querySelectorAll() {
      return [keepCard, deletedCard, ...addedCards].filter((card) => !card.removed);
    },
    querySelector(selector) {
      if (selector === "#create-server") return { remove() {} };
      return null;
    },
    insertAdjacentHTML(position, html) {
      this.innerHTML += html;
      const match = html.match(/data-op-card="([^"]+)"/);
      if (match) {
        addedCards.push({
          dataset: { opCard: match[1] },
          remove() {
            this.removed = true;
          },
          querySelector() {
            return { className: "", textContent: "", innerHTML: "" };
          },
        });
      }
    },
  };
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [],
    "/api/cloud/operations": [makeOp("keep"), makeOp("delete")],
    "/api/cloud/quotas": {
      nodes: [
        { id: "removed-exit", name: "Removed server", enabled: true, ready: true },
        { id: "live-exit", name: "Active server", enabled: true, ready: true },
      ],
      budgets: [],
    },
    "/api/cloud/replicas": [],
  });
  await flush();
  vm.runInContext('currentTab = "service"', p.context);
  await vm.runInContext("service()", p.context);
  const originalView = p.el("#app").innerHTML;
  p.el("#app").querySelector = (selector) =>
    selector === "#cloud-operations" ? operations : p.el(selector);

  p.responses["/api/cloud/operations"] = [
    makeOp("keep", "unknown"),
    makeOp("new"),
    makeOp("delete", "deleted"),
  ];
  await vm.runInContext("refreshOperationCards(viewVersion)", p.context);

  assert.equal(p.el("#app").innerHTML, originalView);
  assert.equal(keepCard.removed, undefined);
  assert.equal(keepCard.price, keepPrice);
  assert.equal(keepStatus.textContent, "Результат создания проверяется");
  assert.equal(deletedCard.removed, true);
  assert.ok(addedCards.some((card) => card.dataset.opCard === "new"));
  assert.doesNotMatch(p.el("#server-capacity").innerHTML, /Removed server/);
  assert.match(p.el("#server-capacity").innerHTML, /Active server/);

  await vm.runInContext("service(true)", p.context);
  assert.equal(keepCard.log, openLog);
  assert.equal(keepCard.log.open, true);
  assert.equal(addedCards.filter((card) => card.dataset.opCard === "new").length, 1);
  assert.doesNotMatch(p.el("#server-capacity").innerHTML, /Removed server/);

  p.context.ops = operations;
  vm.runInContext("reconcileCloudOperations(ops, [], true, null)", p.context);
  assert.equal(keepCard.removed, undefined);
  assert.equal(keepCard.price, keepPrice);
  assert.match(operations.innerHTML, /data-cloud-unavailable/);
});

test("reinstall is offered only for a failed staged cloud identity", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  for (const [change, allowed] of [
    [{}, true],
    [{ state: "ready" }, false],
    [{ phase: "install" }, false],
    [{ exit_id: "other" }, false],
    [{ serves_subscription_ingress: true }, false],
  ]) {
    p.context.recovery = { id: "op", exit_id: "op", instance_id: "vm", state: "failed", phase: "verify", ...change };
    const html = vm.runInContext("cloudOperationDetailsHTML(recovery)", p.context);
    assert.equal(html.includes('data-action="reinstall"'), allowed);
  }
});

test("route continuation exposes only failed stages", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  const failed = { id: "op", state: "failed", phase: "apply", error: "route_application_timeout" };
  p.context.failed = failed;
  const failedHTML = vm.runInContext("cloudOperationDetailsHTML(failed)", p.context);
  assert.match(failedHTML, /data-action="retry"/);
  assert.match(failedHTML, /Продолжить этап/);
  assert.equal(vm.runInContext("phases.apply", p.context), "Применение маршрута на bridge");
  const unknown = { id: "op", state: "unknown", phase: "creating" };
  p.context.unknown = unknown;
  const unknownHTML = vm.runInContext("cloudOperationDetailsHTML(unknown)", p.context);
  assert.ok(!unknownHTML.includes('data-action="retry"'));
});

test("traffic activity is separate from permission and does not imply online", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  const now = Date.now();
  p.context.recent = {
    active: true,
    pending: false,
    last_traffic_at: new Date(now - 30000).toISOString(),
  };
  assert.equal(
    vm.runInContext("usage(recent)", p.context),
    "Трафик за последние 2 мин",
  );
  assert.ok(
    vm.runInContext("status(recent)", p.context).includes("Доступ разрешён"),
  );
  assert.equal(
    vm.runInContext("usage({active:true,last_traffic_at:null})", p.context),
    "Трафик ещё не зафиксирован",
  );
  p.context.old = {
    active: true,
    last_traffic_at: new Date(now - 3 * 86400000).toISOString(),
  };
  assert.equal(vm.runInContext("usage(old)", p.context), "Без трафика 3 дн");
  assert.ok(
    vm
      .runInContext("status({active:false,pending:false})", p.context)
      .includes("Доступ отозван"),
  );
  assert.ok(
    vm
      .runInContext("status({active:false,pending:true})", p.context)
      .includes("Отзываем доступ"),
  );
  assert.ok(
    !vm
      .runInContext("usage({...recent,active:false})", p.context)
      .includes("последние 2 мин"),
  );
});

test("personal statistics include all devices and survive disabled access", async () => {
  const traffic = {
    month: "2026-09",
    uplink_bytes: 10,
    downlink_bytes: 20,
    routes: [
      { tag: "ams", name: "Амстердам", uplink_bytes: 10, downlink_bytes: 20 },
    ],
    days: [],
    day_routes: [
      {
        tag: "ams",
        bucket: "2026-09-08",
        uplink_bytes: 10,
        downlink_bytes: 20,
      },
    ],
  };
  const p = page(true, {
    "/api/self": {
      registered: true,
      is_admin: false,
      member: {
        uuid: "owner",
        active: false,
        pending: false,
        last_traffic_at: null,
      },
    },
    "/api/self/traffic": traffic,
  });
  await flush();
  assert.ok(p.el("#self-traffic").innerHTML.includes("Амстердам"));
  assert.ok(p.el("#self-traffic").innerHTML.includes("30 Б"));
  assert.ok(p.el("#app").innerHTML.includes("Трафик ещё не зафиксирован"));
  assert.ok(p.calls.every((c) => c.path.startsWith("/api/self")));
});
test("statistics failure does not replace personal cabinet or hide connect controls", async () => {
  const p = page(true, {
    "/api/self": {
      registered: true,
      is_admin: false,
      member: { uuid: "owner", active: true, pending: false },
    },
    "/api/self/exits": { exits: [], profiles: [] },
  });
  await flush();
  assert.ok(p.el("#app").innerHTML.includes('id="connect"'));
  assert.ok(
    p.el("#self-traffic").innerHTML.includes("Статистика временно недоступна"),
  );
  assert.ok(!p.el("#app").innerHTML.includes("Кабинет недоступен"));
  assert.equal(typeof p.el("#refresh-self-traffic").onclick, "function");
});
test("creation errors remain visible inside the confirmation dialog", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  vm.runInContext(
    `modal('<button id="buy">Подтвердить</button>');button('buy',async()=>{throw new Error('IP bridge не разрешён в Vultr')})`,
    p.context,
  );
  await p.el("#buy").onclick();
  assert.equal(p.el("#dialog-error").hidden, false);
  assert.equal(
    p.el("#dialog-error").textContent,
    "IP bridge не разрешён в Vultr",
  );
  assert.equal(p.el("#dialog").open, true);
  assert.equal(p.el("#buy").disabled, false);
});

test("person charts select period and route without historical unattributed totals", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  p.context.chart = {
    month: "2026-09",
    today: "2026-09-08",
    routes: [
      { tag: "direct", name: "Yandex Cloud" },
      { tag: "ams", name: "Амстердам" },
      { tag: "unknown", name: "Старый трафик" },
    ],
    day_routes: [
      {
        bucket: "2026-09-08",
        tag: "ams",
        uplink_bytes: 10,
        downlink_bytes: 20,
      },
      { bucket: "2026-09-08", tag: "unknown", downlink_bytes: 999 },
    ],
    hours: [{ bucket: "2026-09-08 12:00", tag: "direct", downlink_bytes: 4 }],
  };
  assert.equal(
    vm.runInContext(
      'personTrafficData(chart,"month").selected.length',
      p.context,
    ),
    1,
  );
  assert.equal(
    vm.runInContext('personTrafficData(chart,"day").buckets.length', p.context),
    24,
  );
  assert.equal(
    vm.runInContext(
      'personTrafficData(chart,"month").buckets.length',
      p.context,
    ),
    30,
  );
  assert.equal(
    vm.runInContext(
      'personTrafficData(chart,"day","ams").selected.length',
      p.context,
    ),
    0,
  );
  vm.runInContext(
    'renderTrafficChart(document.querySelector("#person-traffic"),chart)',
    p.context,
  );
  const html = p.el("#person-traffic").innerHTML;
  assert.ok(html.includes("30 Б"));
  assert.ok(html.includes("Потребление по дням"));
  assert.ok(!html.includes("Старый трафик"));
  assert.ok(!html.includes("999"));
});

test("traffic directions combine recreated exits without losing points or merging unrelated nodes", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  p.context.chart = {
    month: "2026-09", today: "2026-09-08",
    routes: [
      { tag: "direct", name: "Legacy provider" },
      { tag: "to-exit-old", name: "Test City", group: "location:XX:test city" },
      { tag: "to-exit-new", name: "Test City", group: "location:XX:test city" },
      { tag: "to-exit-other", name: "Test City", group: "location:YY:test city" },
      { tag: "to-exit-missing", name: "Другой или удалённый выход" },
    ],
    day_routes: [
      { bucket: "2026-09-08", tag: "direct", downlink_bytes: 5 },
      { bucket: "2026-09-08", tag: "to-exit-old", uplink_bytes: 10, downlink_bytes: 20 },
      { bucket: "2026-09-08", tag: "to-exit-new", uplink_bytes: 30, downlink_bytes: 40 },
      { bucket: "2026-09-08", tag: "to-exit-other", downlink_bytes: 7 },
    ],
    hours: [
      { bucket: "2026-09-08 12:00", tag: "to-exit-old", downlink_bytes: 2 },
      { bucket: "2026-09-08 12:00", tag: "to-exit-new", downlink_bytes: 3 },
    ],
    limits: [{ name: "Test City", exit_id: "new", state: "available", remaining_bytes: 99 }],
  };
  const original = JSON.stringify(p.context.chart);
  const grouped = vm.runInContext('personTrafficData(chart,"month")', p.context);
  assert.equal(grouped.routes.length, 4);
  const tag = grouped.routes.find((r) => r.group === "location:XX:test city").tag;
  p.context.selectedTag = tag;
  assert.equal(vm.runInContext('personTrafficData(chart,"month",selectedTag).selected.reduce((n,p)=>n+(p.uplink_bytes||0)+(p.downlink_bytes||0),0)', p.context), 100);
  assert.equal(vm.runInContext('personTrafficData(chart,"day",selectedTag).selected.reduce((n,p)=>n+(p.downlink_bytes||0),0)', p.context), 5);
  vm.runInContext('renderTrafficChart(document.querySelector("#person-traffic"),chart,"month",selectedTag)', p.context);
  const html = p.el("#person-traffic").innerHTML;
  assert.ok(html.includes("100 Б"));
  assert.ok(html.includes("99 Б"));
  vm.runInContext('renderTrafficChart(document.querySelector("#person-traffic"),chart)', p.context);
  assert.ok(p.el("#person-traffic").innerHTML.includes("Напрямую с bridge"));
  assert.ok(!p.el("#person-traffic").innerHTML.includes("Legacy provider"));
  assert.equal(JSON.stringify(p.context.chart), original);
});

test("invitations identify recipient and group with links", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [],
    "/api/enrollment/group": {
      chat_id: -100123,
      title: "Друзья",
      enabled: true,
      group_url: "https://t.me/+test",
    },
    "/api/enrollment/invites": [
      {
        id: 1,
        recipient: 123,
        recipient_name: "Анна <Test>",
        expires_at: "2099-01-01",
      },
    ],
  });
  await flush();
  await vm.runInContext("invites()", p.context);
  const html = p.el("#app").innerHTML;
  assert.ok(html.includes("Анна &lt;Test&gt;"));
  assert.ok(html.includes("tg://user?id=123"));
  assert.ok(html.includes("Открыть группу"));
  assert.ok(html.includes("Друзья"));
});
test("account balance stays independent of server operations", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [],
    "/api/cloud/account": {
      balance: 12.5,
      pending_charges: 1.25,
      observed_at: "2026-09-08T00:00:00Z",
    },
  });
  await flush();
  await vm.runInContext("loadCloudAccount()", p.context);
  assert.ok(p.el("#cloud-account").innerHTML.includes("12,50"));
  assert.ok(p.el("#cloud-account").innerHTML.includes("1,25"));
});

test("ready server separates operation, tunnel health and billing", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  p.context.o = {
    state: "ready",
    phase: "ready",
    charged: true,
    exit_id: "atl",
  };
  p.context.capacity = {
    nodes: [{ id: "atl", name: "Атланта", enabled: true, ready: true }],
    budgets: [{ exit_id: "atl", source: "vultr", monthly_bytes: 3000000000000 }],
  };
  assert.equal(
    vm.runInContext("serverStateLabel(o,capacity)", p.context),
    "Серверная проверка HTTPS прошла",
  );
  const capacityHTML = vm.runInContext("serverCapacityHTML(capacity)", p.context);
  assert.match(capacityHTML, /Серверная проверка HTTPS прошла/);
  assert.match(capacityHTML, /Начисленный пул Vultr \(справочно\)/);
  assert.match(capacityHTML, /общие для всех выходов Vultr/);
  assert.equal(
    vm.runInContext("serverBillingLabel(o)", p.context),
    "Оплата продолжается",
  );
  p.context.capacity.nodes[0].ready = false;
  assert.match(
    vm.runInContext("serverStateLabel(o,capacity)", p.context),
    /туннель недоступен/,
  );
  p.context.o.state = "unknown";
  assert.match(
    vm.runInContext("serverStateLabel(o,capacity)", p.context),
    /Результат создания проверяется/,
  );
  p.context.o.state = "failed";
  assert.match(
    vm.runInContext("serverStateLabel(o,capacity)", p.context),
    /Ошибка/,
  );
  assert.equal(
    vm.runInContext("serverBillingLabel(o)", p.context),
    "Оплата продолжается",
  );
  assert.match(
    vm.runInContext("applicationLabel({state:'error'})", p.context),
    /Ошибка применения/,
  );
});

test("automatic route highlights the selected exit without a country selector", async () => {
  const route = {
    selected_exit_id: "atl",
    effective_exit_id: "ams",
    application: { state: "error" },
    route_reason: "monthly_user_limit_exhausted",
	exits: [
	  { id: "ams", display_name: "Нидерланды", quota_kind: "separate", reachable: true },
	  { id: "atl", display_name: "США", quota_kind: "shared", reachable: true },
	],
	profiles: [{ name: "США", effective_exit_id: "atl" }],
  };
  const p = page(true, {
    "/api/self": { registered: true, member: { active: true } },
    "/api/self/exits": route,
  });
  await flush();
  const html = p.el("#locations").innerHTML;
  assert.match(html, /Ошибка применения/);
	assert.match(html, /data-route-exit="ams"/);
	assert.match(html, /Нидерланды.*Авто · ожидает применения/);
	assert.match(html, /Нидерланды.*Отдельная квота/);
	assert.match(html, /США.*Общая квота/);
	assert.doesNotMatch(html, /США\s*→\s*США/);
	assert.ok(!html.includes("Vultr"));
  assert.match(html, /доступной вам квотой/);
  assert.match(html, /возвращается к основному после восстановления/);
  assert.ok(!html.includes('id="preferred"'));
  assert.ok(!html.includes('id="save-location"'));
  assert.ok(
    !p.calls.some(
      (c) =>
        c.path.includes("exit-selection") || c.path.includes("subscription"),
    ),
  );
});

test("subscription ingress cannot be deleted or replaced from server card", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [],
    "/api/cloud/operations": [
      {
        id: "ingress",
        instance_id: "vps",
        state: "ready",
        phase: "ready",
        charged: true,
        serves_subscription_ingress: true,
        offer: {
          region: { city: "Atlanta" },
          plan: { id: "vc2" },
          price: { monthly_cost: 5 },
        },
      },
    ],
    "/api/cloud/replicas": [],
  });
  await flush();
  await vm.runInContext("service()", p.context);
  const html = p.el("#app").innerHTML;
  assert.ok(html.includes("Обслуживает подписки"));
  assert.ok(!html.includes('data-action="delete"'));
  assert.ok(!html.includes("data-replace="));
});

test("ingress diagnostics hides obsolete experiments and escapes primary strings", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  p.context.states = [
    { id: "primary", ready: true, phase: "server_path_ready" },
    { id: "experimental", ready: false, phase: "<SCRIPT>unsafe</SCRIPT>" },
  ];
  const html = vm.runInContext("ingressHealthHTML(states)", p.context);
  assert.match(html, /Основной вход/);
  assert.doesNotMatch(html, /Экспериментальный вход/);
  assert.doesNotMatch(html, /<script>|unsafe/i);
  p.context.states = [
    { id: "primary", ready: false, phase: "<SCRIPT>unsafe</SCRIPT>" },
  ];
  const unsafePrimary = vm.runInContext("ingressHealthHTML(states)", p.context);
  assert.match(unsafePrimary, /Недоступен/);
  assert.doesNotMatch(unsafePrimary, /<script>/i);
  assert.ok(unsafePrimary.includes("&lt;SCRIPT&gt;"));
});

test("routing map follows live exits and keeps its explanation open during refresh", async () => {
  const p = page(true, {
    "/api/self": { registered: false, is_admin: false },
    "/api/self/exits": {
      exits: [{ id: "old", display_name: "Old exit", reachable: true }],
      effective_exit_id: "old",
      application: { state: "applied" },
    },
  });
  await flush();
  p.context.viewVersion = 5;
  await vm.runInContext("locations()", p.context);
  const target = p.el("#locations");
  assert.match(target.innerHTML, /data-route-exit="old"/);
  assert.match(target.innerHTML, /Ваше устройство/);
  assert.match(target.innerHTML, /Bridge/);
  assert.doesNotMatch(target.innerHTML, /США\s*→\s*США/);

  target.querySelector("details").open = true;
  p.context.document.activeElement = target.querySelector("summary");
  p.responses["/api/self/exits"] = {
    exits: [
      { id: "new", display_name: "New exit", reachable: true },
      { id: "backup", display_name: "Backup", reachable: false },
      { id: "spare", display_name: "Spare", reachable: true },
    ],
    effective_exit_id: "new",
    application: { state: "applied" },
  };
  p.timers.at(-1).callback();
  await flush();
  assert.doesNotMatch(target.innerHTML, /data-route-exit="old"/);
  assert.match(target.innerHTML, /data-route-exit="new"/);
  assert.match(target.innerHTML, /data-route-exit="backup"/);
  assert.match(target.innerHTML, /data-route-exit="spare"/);
  assert.match(target.innerHTML, /Туннель доступен/);
  assert.match(target.innerHTML, /Туннель недоступен/);
  assert.equal(target.querySelector("details").open, true);
  assert.equal(target.querySelector("summary").focused, true);
});

test("diagnostics separates primary database identity from bridge standby observation", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [],
    "/api/health": { bridge: { internet_ok: true }, exits: [] },
    "/api/alerts/recent?limit=10": [],
    "/api/cloud/replicas": [
      {
        id: "bridge",
        name: "Bridge PostgreSQL standby",
        source: "primary",
        state: "streaming",
      },
    ],
    "/api/database": {
      primary_host: "192.0.2.40",
      configured_host: "127.0.0.1",
      configured_port: 5432,
      reachable: true,
      observed_role: "primary",
    },
  });
  await flush();
  await vm.runInContext("diagnostics()", p.context);
  let html = p.el("#network-health").innerHTML;
  assert.match(html, /Primary PostgreSQL/);
  assert.match(html, /Сервер: 192\.0\.2\.40 · проверка через пул приложения/);
  let primaryRow = html
    .split(/(?=<div class="route-row">)/)
    .find((row) => row.includes("Primary PostgreSQL"));
  assert.ok(primaryRow);
  assert.match(primaryRow, /Доступен · primary/);
  assert.doesNotMatch(primaryRow, /127\.0\.0\.1/);
  let replicaHTML = p.el("#network-replication").innerHTML;
  assert.match(replicaHTML, /Bridge PostgreSQL standby/);
  assert.match(replicaHTML, /Поток репликации работает/);
  assert.match(replicaHTML, /badge good/);

  p.responses["/api/cloud/replicas"] = [
    { id: "bridge", state: "syncing" },
  ];
  await vm.runInContext("diagnostics()", p.context);
  replicaHTML = p.el("#network-replication").innerHTML;
  assert.match(replicaHTML, /Копия синхронизируется/);
  assert.match(replicaHTML, /badge wait/);

  p.responses["/api/cloud/replicas"] = [
    { id: "bridge", state: "disconnected" },
  ];
  await vm.runInContext("diagnostics()", p.context);
  replicaHTML = p.el("#network-replication").innerHTML;
  assert.match(replicaHTML, /badge bad/);
  assert.match(replicaHTML, /Нет потока репликации/);

  p.responses["/api/cloud/replicas"] = [
    { id: "bridge", state: "streaming" },
  ];
  p.responses["/api/database"] = new Error("primary unavailable");
  await vm.runInContext("diagnostics()", p.context);
  html = p.el("#network-health").innerHTML;
  primaryRow = html
    .split(/(?=<div class="route-row">)/)
    .find((row) => row.includes("Primary PostgreSQL"));
  assert.ok(primaryRow);
  assert.match(primaryRow, /Состояние неизвестно/);
  replicaHTML = p.el("#network-replication").innerHTML;
  assert.match(replicaHTML, /Поток репликации работает/);
});

test("replica status remains visible when network health is unavailable", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/health": new Error("health unavailable"),
    "/api/alerts/recent?limit=10": [],
    "/api/cloud/replicas": [
      { id: "bridge", state: "streaming", replay_lag_bytes: 12 },
    ],
    "/api/database": { primary_host: "192.0.2.40", reachable: true },
  });
  await flush();
  await vm.runInContext("diagnostics()", p.context);
  assert.match(p.el("#network-health").innerHTML, /Состояние сети/);
  assert.match(p.el("#network-health").innerHTML, /Повторить/);
  assert.match(p.el("#network-replication").innerHTML, /Поток репликации работает/);
  assert.match(p.el("#network-replication").innerHTML, /Отставание WAL: 12 байт/);
});

test("replica endpoint failure is shown separately from unknown replica state", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/health": { bridge: { internet_ok: true }, exits: [] },
    "/api/alerts/recent?limit=10": [],
    "/api/cloud/replicas": new Error("replica endpoint unavailable"),
    "/api/database": { primary_host: "192.0.2.40", reachable: true },
  });
  await flush();
  await vm.runInContext("diagnostics()", p.context);
  assert.match(p.el("#network-replication").innerHTML, /Реплика PostgreSQL/);
  assert.match(p.el("#network-replication").innerHTML, /Данные временно недоступны/);
  assert.match(p.el("#network-replication").innerHTML, /Повторить/);
  assert.doesNotMatch(p.el("#network-replication").innerHTML, /Нет потока репликации/);
});

test("overview brings monthly history and config ranking into the main cabinet", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [{ active: true, pending: false }],
    "/api/stats": { total_bytes_month: 1024 },
    "/api/health": {
      bridge: { internet_ok: true },
      exit: { reachable: true, internet_ok: true, name: "Amsterdam" },
    },
    "/api/stats/history?months=12": [
      { Year: 2026, Month: 8, TotalBytes: 1024 },
    ],
    "/api/users": [{ uuid: "test", name: "<unsafe>", total_bytes: 1024 }],
  });
  await flush();
  assert.match(p.el("#overview-history").innerHTML, /Последние 12 месяцев/);
  assert.match(p.el("#overview-top").innerHTML, /&lt;unsafe&gt;/);
  assert.match(p.el("#overview-health").innerHTML, /Серверные проверки прошли/);
  assert.match(p.el("#overview-traffic").innerHTML, /временно недоступны/);
  assert.ok(!p.el("#app").innerHTML.includes("legacy"));
});
test("missing overview data stays unknown rather than showing false zero or health", async () => {
  const p = page(false, { "/api/me": { is_admin: true } });
  await flush();
  assert.match(p.el("#overview-summary").innerHTML, /—/);
  assert.match(p.el("#overview-health").innerHTML, /Нет данных/);
  assert.match(p.el("#overview-history").innerHTML, /Повторить/);
  assert.ok(!p.el("#overview-health").innerHTML.includes("проверки прошли"));
});
test("failure to fetch locations preserves the personal connection action", async () => {
  const p = page(true, {
    "/api/self": { registered: true, member: { uuid: "owner", active: true } },
  });
  await flush();
  assert.match(p.el("#app").innerHTML, /id="connect"/);
  assert.match(p.el("#locations").innerHTML, /Маршрут временно недоступен/);
});
test("archive config cannot export, rotate or enable unsupported access", async () => {
  const p = page(false, { "/api/me": { is_admin: true } });
  await flush();
  const html = vm.runInContext(
    "configControls({uuid:'old',kind:'socks5',is_active:false})",
    p.context,
  );
  assert.ok(html.includes("purge-config"));
  for (const id of [
    "export-config",
    "rotate-config",
    "enable-config",
    "issue-config-sub",
  ])
    assert.ok(!html.includes(id));
});
test("disabling a config sends DELETE on the first click", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/users/legacy": {},
  });
  await flush();
  const user = { uuid: "legacy", kind: "vless", is_active: true };
  p.context.configDetail = async (updated) => {
    p.context.updatedConfig = updated;
  };
  p.context.configUser = user;
  vm.runInContext("bindConfigControls(configUser)", p.context);

  await p.el("#disable-config").click();
  assert.equal(
    p.calls.filter(
      (call) => call.path === "/api/users/legacy" && call.options.method === "DELETE",
    ).length,
    1,
  );
  assert.equal(p.context.updatedConfig.is_active, false);
});
test("enabling a config runs its action on one click without rebinding", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/users/legacy/enable": {},
  });
  await flush();
  const user = { uuid: "legacy", kind: "vless", is_active: false };
  p.context.configDetail = async (updated) => {
    p.context.updatedConfig = updated;
  };
  p.context.configUser = user;
  // Bind once, as the rendered config detail does; one user click must suffice.
  vm.runInContext("bindConfigControls(configUser)", p.context);
  const enable = p.el("#enable-config");
  await enable.click();
  assert.equal(
    p.calls.filter(
      (call) =>
        call.path === "/api/users/legacy/enable" &&
        call.options.method === "POST",
    ).length,
    1,
  );
  assert.equal(p.context.updatedConfig.is_active, true);
  assert.equal(enable.disabled, false);
});
test("purge requires typed confirmation and addresses only the selected config", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/users/old/purge": {},
    "/api/users": [],
  });
  await flush();
  vm.runInContext(
    "bindConfigControls({uuid:'old',kind:'vless',is_active:false})",
    p.context,
  );
  await p.el("#purge-config").onclick();
  p.el("#purge-word").value = "wrong";
  await p.el("#purge-confirm").onclick();
  assert.ok(!p.calls.some((c) => c.options.method === "DELETE"));
  p.el("#purge-word").value = "УДАЛИТЬ";
  await p.el("#purge-confirm").onclick();
  assert.equal(
    p.calls.filter(
      (c) => c.path === "/api/users/old/purge" && c.options.method === "DELETE",
    ).length,
    1,
  );
});
test("config creation sends only VLESS and the entered name", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/users": {
      user: { uuid: "created", name: "Work", kind: "vless", is_active: true },
    },
  });
  await flush();
  vm.runInContext("editConfigName(null)", p.context);
  p.el("#config-name").value = " Work ";
  await p.el("#save-config").onclick();
  const call = p.calls.find(
    (c) => c.path === "/api/users" && c.options.method === "POST",
  );
  assert.deepEqual(JSON.parse(call.options.body), {
    name: "Work",
    kind: "vless",
  });
});
test("no cabinet or preview references removed interface or duplicated preview assets", () => {
  const root = require("node:path").join(
    __dirname,
    "../internal/bot/embed/miniapp",
  );
  for (const file of [
    "index.html",
    "member.html",
    "cabinet.js",
    "dashboard.js",
    "configs.js",
    "preview/admin.html",
    "preview/member.html",
    "preview/demo.js",
  ])
    assert.ok(
      !fs
        .readFileSync(require("node:path").join(root, file), "utf8")
        .includes("legacy.html"),
      file,
    );
  for (const file of [
    "legacy.html",
    "app.js",
    "style.css",
    "preview/cabinet.js",
    "preview/cabinet.css",
  ])
    assert.ok(!fs.existsSync(require("node:path").join(root, file)), file);
  assert.match(
    fs.readFileSync(
      require("node:path").join(root, "preview/admin.html"),
      "utf8",
    ),
    /\.\.\/cabinet.js/,
  );
});

test("all embedded HTML assets still exist after removing the legacy UI", () => {
  const path = require("node:path");
  const root = path.join(__dirname, "../internal/bot/embed/miniapp");
  for (const file of [
    "index.html",
    "member.html",
    "happ.html",
    "preview/admin.html",
    "preview/member.html",
  ]) {
    const html = fs.readFileSync(path.join(root, file), "utf8");
    for (const match of html.matchAll(
      /(?:src|href)="([^"?#]+\.(?:js|css))(?:[?#][^"]*)?"/g,
    )) {
      if (/^https?:/.test(match[1])) continue;
      const asset = match[1].startsWith("/")
        ? path.join(root, match[1])
        : path.resolve(root, path.dirname(file), match[1]);
      assert.ok(fs.existsSync(asset), `${file}: ${match[1]}`);
    }
  }
});

test("shared quota stays whole across route and period filters beside separate reserve", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  p.context.chart = {
    month: "2026-09", today: "2026-09-08",
	  routes: [{ tag: "exit-a", name: "Нидерланды", quota_kind: "shared" }, { tag: "exit-b", name: "США", quota_kind: "shared" }, { tag: "direct", name: "Напрямую с bridge", quota_kind: "direct" }],
	  quota_pools: [{ quota_kind: "shared", period: "2026-09", personal_limit_bytes: 900, used_bytes: 200, remaining_bytes: 700, observed_at: "2026-09-08T12:00:00Z", resets_at: "2026-10-01T00:00:00Z", state: "available" }],
    limits: [{ name: "Резерв <тест>", is_fallback: true, remaining_bytes: 99, state: "available" }],
  };
  for (const expression of ['"month"', '"day", "exit-a"', '"month", "exit-b"']) {
    vm.runInContext(`renderTrafficChart(document.querySelector("#person-traffic"),chart,${expression})`, p.context);
    const html = p.el("#person-traffic").innerHTML;
	assert.equal((html.match(/data-quota-kind="shared"/g) || []).length, 1);
	for (const text of ["900 Б", "200 Б", "700 Б", "99 Б", "Резерв &lt;тест&gt;", "Последние подтверждённые данные", "Общая квота", "Личный предел — 25% от безопасного общего пула Vultr после 20% резерва", "UTC", "Ручной резерв"]) assert.ok(html.includes(text), text);
	assert.ok(html.includes("безопасного общего пула Vultr"));
    assert.ok(!html.includes("Invalid Date"));
  }
});

test("pool states distinguish unknown confirmation, emergency and exhaustion without promising reserve", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
	p.context.quota = { quota_pools: [{ quota_kind: "shared", state: "unknown", remaining_bytes: 777, observed_at: null }] };
  let html = vm.runInContext("trafficQuotasHTML(quota)", p.context);
  assert.ok(html.includes("Уточняется"));
  assert.ok(html.includes("Ожидаем подтверждённые данные"));
  assert.ok(!html.includes("777 Б"));
  assert.ok(!html.includes("Invalid Date"));
  p.context.quota.quota_pools[0].state = "emergency";
  html = vm.runInContext("trafficQuotasHTML(quota)", p.context);
  assert.ok(html.includes("аварийный запас"));
  assert.ok(html.includes("777 Б"));
  p.context.quota.quota_pools[0].state = "exhausted";
  html = vm.runInContext("trafficQuotasHTML(quota)", p.context);
	assert.ok(html.includes("Общая квота исчерпана"));
  assert.ok(!html.includes("резерв доступен"));
});

test("legacy traffic responses keep per-exit limits and empty quotas render nothing", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  p.context.quota = { limits: [{ name: "Выход A", remaining_bytes: 55, state: "available" }] };
  const html = vm.runInContext("trafficQuotasHTML(quota)", p.context);
  assert.ok(html.includes("Выход A"));
  assert.ok(html.includes("55 Б"));
  assert.ok(!html.includes("Общий трафик Vultr"));
  assert.equal(vm.runInContext("trafficQuotasHTML({})", p.context), "");
});

test("bridge standby uses dedicated topology and refreshes independently of operations", async () => {
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [],
    "/api/cloud/operations": [],
    "/api/cloud/replicas": [{ id: "bridge", name: "Bridge PostgreSQL standby", source: "primary", state: "streaming", replay_lag_bytes: 0, checked_at: "2026-01-01T00:00:00Z" }],
  });
  await flush();
  await vm.runInContext("service()", p.context);
  const html = p.el("#app").innerHTML;
  assert.match(html, /Основная БД на отдельном database/);
  assert.match(html, /standby-копия на bridge/);
  assert.match(html, /Наблюдение с primary/);
  assert.match(html, /отставание WAL: 0 байт/);
  assert.doesNotMatch(html, /Основная БД на bridge|Свободное место|Ещё не настроена/);
  const timer = p.timers.findLast((t) => t.delay === 10000 && !t.cancelled);
  assert.ok(timer, "standby refresh is required even with no cloud operations");
  p.responses["/api/cloud/replicas"] = [{ name: "Bridge PostgreSQL standby", state: "disconnected" }];
  await timer.callback();
  assert.match(p.el("#bridge-replicas").innerHTML, /Нет потока репликации/);
  assert.doesNotMatch(p.el("#bridge-replicas").innerHTML, /Копия обновляется/);
  delete p.responses["/api/cloud/replicas"];
  const retry = p.timers.findLast((t) => t.delay === 10000 && !t.cancelled);
  await retry.callback();
  assert.match(p.el("#bridge-replicas").innerHTML, /временно недоступно/);
  const next = p.timers.findLast((t) => t.delay === 10000 && !t.cancelled);
  vm.runInContext("viewVersion++", p.context);
  const requests = p.calls.length;
  await next.callback();
  assert.equal(p.calls.length, requests, "stale view must not keep polling standby");
});

test("legacy exit replication states cannot claim bridge configuration", async () => {
  const p = page(false, { "/api/me": { is_admin: true }, "/api/members": [] });
  await flush();
  const html = vm.runInContext('bridgeReplicasHTML([{name:"Bridge",state:"not_configured"}])', p.context);
  assert.match(html, /Состояние копии неизвестно/);
  assert.doesNotMatch(html, /Ещё не настроена/);
});


test("cached subscription revalidates UUID and shares simultaneous issuance", async () => {
  const p = page(true, {
    "/api/self": { registered: true, member: { uuid: "old", active: true } },
    "/api/self/exits": { exits: [], profiles: [] },
    "/api/self/subscription": { url: "https://example.com/old", import_url: "https://example.com/old-import" },
  });
  await flush();
  await p.el("#copy-sub").onclick();
  p.responses["/api/self"].member.uuid = "new";
  p.responses["/api/self/subscription"] = { url: "https://example.com/new", import_url: "https://example.com/new-import" };
  await Promise.all([p.el("#copy-sub").onclick(), p.el("#connect").onclick()]);
  assert.deepEqual(p.copied, ["https://example.com/old", "https://example.com/new"]);
  assert.deepEqual(p.opened, ["https://example.com/new-import"]);
  assert.equal(p.calls.filter((c) => c.path === "/api/self/subscription").length, 2);
  p.responses["/api/self"].member.active = false;
  await p.el("#copy-sub").onclick();
  assert.equal(p.copied.length, 2);
});

test("pending person polls completion and ignores responses after navigation", async () => {
  const member = { telegram_id: 42, uuid: "old", name: "Member", active: true, pending: true };
  const p = page(false, {
    "/api/me": { is_admin: true },
    "/api/members": [member],
    "/api/members/42/traffic": { months: [] },
  });
  await flush();
  p.context.member = member;
  vm.runInContext("person(member)", p.context);
  p.responses["/api/members"] = [{ ...member, uuid: "new", pending: false }];
  const timer = p.timers.at(-1);
  await timer.callback();
  assert.doesNotMatch(p.el("#app").innerHTML, /Подтверждаем|Применяется/);
  assert.match(p.el("#app").innerHTML, /Доступ разрешён/);
  assert.equal(p.timers.at(-1), timer);

  vm.runInContext("person(member)", p.context);
  const staleTimer = p.timers.at(-1);
  const inFlight = staleTimer.callback();
  await vm.runInContext("people()", p.context);
  const html = p.el("#app").innerHTML;
  await inFlight;
  assert.equal(p.el("#app").innerHTML, html);
  assert.match(html, /people-list/);
  const calls = p.calls.length;
  await staleTimer.callback();
  assert.equal(p.calls.length, calls);
});
