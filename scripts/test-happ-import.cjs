const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const root = path.join(__dirname, "../internal/bot/embed/miniapp");
const token = "A".repeat(43);

function page(hash, protocol = "https:", origin = "https://vpn.example:8443") {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id))
      elements.set(id, {
        hidden: true,
        addEventListener(name, fn) {
          this[name] = fn;
        },
      });
    return elements.get(id);
  };
  const history = [];
  vm.runInNewContext(fs.readFileSync(path.join(root, "happ.js"), "utf8"), {
    window: {
      location: { hash, protocol, origin, pathname: "/happ" },
      history: {
        replaceState(...args) {
          history.push(args);
        },
      },
    },
    document: { getElementById: element },
    navigator: { clipboard: { writeText: async () => {} } },
  });
  return { element, history };
}
test("browser import preserves HTTPS host, port and token", () => {
  const { element, history } = page("#" + token);
  assert.equal(
    element("launch-happ").href,
    "happ://add/https://vpn.example:8443/sub/" + token,
  );
  assert.equal(
    element("import-subscription").value,
    "https://vpn.example:8443/sub/" + token,
  );
  assert.equal(element("import-actions").hidden, false);
  assert.equal(history[0][2], "/happ");
});
test("invalid fragment or plaintext origin cannot create an import link", () => {
  for (const [hash, protocol] of [
    ["#https://evil.example", "https:"],
    ["#" + token, "http:"],
  ]) {
    assert.equal(page(hash, protocol).element("launch-happ").href, undefined);
  }
});
test("config subscription builds an HTTPS import preserving origin and token", () => {
  const context = vm.createContext({ URL });
  vm.runInContext(
    fs.readFileSync(path.join(root, "configs.js"), "utf8"),
    context,
  );
  context.raw = "https://vpn.example:8443/sub/" + token;
  assert.equal(
    vm.runInContext("subscriptionImportURL(raw)", context),
    "https://vpn.example:8443/happ#" + token,
  );
  for (const raw of [
    "http://vpn.example/sub/" + token,
    "https://vpn.example/sub/not-a-token",
  ]) {
    context.raw = raw;
    assert.throws(() => vm.runInContext("subscriptionImportURL(raw)", context));
  }
});

test("standard HTTPS ingress preserves token without adding the backend port", () => {
  const { element } = page("#" + token, "https:", "https://vpn.example");
  assert.equal(
    element("launch-happ").href,
    "happ://add/https://vpn.example/sub/" + token,
  );
});
