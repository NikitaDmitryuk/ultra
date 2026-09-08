const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.join(__dirname, '../internal/bot/embed/miniapp');
const token = 'A'.repeat(43);

function page(hash, protocol = 'https:') {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {hidden: true, addEventListener(name, fn) {this[name] = fn;}});
    return elements.get(id);
  };
  const history = [];
  vm.runInNewContext(fs.readFileSync(path.join(root, 'happ.js'), 'utf8'), {
    window: {location: {hash, protocol, origin: 'https://vpn.example:8443', pathname: '/happ'},
      history: {replaceState(...args) {history.push(args);}}},
    document: {getElementById: element}, navigator: {clipboard: {writeText: async () => {}}},
  });
  return {element, history};
}
test('browser import preserves HTTPS host, port and token', () => {
  const {element, history} = page('#' + token);
  assert.equal(element('launch-happ').href, 'happ://add/https://vpn.example:8443/sub/' + token);
  assert.equal(element('import-subscription').value, 'https://vpn.example:8443/sub/' + token);
  assert.equal(element('import-actions').hidden, false);
  assert.equal(history[0][2], '/happ');
});
test('invalid fragment or plaintext origin cannot create an import link', () => {
  for (const [hash, protocol] of [['#https://evil.example', 'https:'], ['#' + token, 'http:']]) {
    assert.equal(page(hash, protocol).element('launch-happ').href, undefined);
  }
});
test('Mini App opens HTTPS import page through Telegram external browser API', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  const source = app.slice(app.indexOf('async function issueSubscription()'), app.indexOf('async function copySubscription()'));
  let url, opened, prevented = false;
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {getAttribute() {return this.href;}});
    return elements.get(id);
  };
  const context = vm.createContext({URL, subscriptionBusy: false, currentUserUUID: 'test',
    setSubscriptionBusy() {}, showToast(message) {throw new Error(message);},
    api: async () => ({url: 'https://vpn.example:8443/sub/' + token}),
    document: {getElementById: element},
    tg: {openLink(link) {opened = link;}}, window: {open() {throw new Error('unexpected fallback');}},
  });
  vm.runInContext(source, context);
  return vm.runInContext('issueSubscription()', context).then(() => {
    url = element('subscription-happ').href;
    assert.equal(url, 'https://vpn.example:8443/happ#' + token);
    context.event = {preventDefault() {prevented = true;}};
    vm.runInContext('openHapp(event)', context);
    assert.equal(opened, url);
    assert.equal(prevented, true);
  });
});
