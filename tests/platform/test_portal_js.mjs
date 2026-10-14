import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const js = readFileSync(new URL('../../apps/portal/app.js', import.meta.url), 'utf8');
const ids = ['apishield-agent','accessfix-ai','specforge-ai','agenttest-lab','datareconcile-ai'];
const products = ids.map((id) => ({
  id, title: id, description: 'Synthetic UI test', domain: 'test',
  platform_route: '/app/' + id,
}));
const fleet = (result = 'PASS', unavailable = []) => ({
  schema:'forgeworks-portal-staging-services-v1',
  environment:'staging',result,
  services: ids.map(product => ({
    product, status: unavailable.includes(product) ? 'unavailable' : 'ready',
  })),
  business_access:'NOT_ENABLED',production_acceptance:'NOT_ACCEPTED',
});

class Element {
  constructor() {
    this.children = [];
    this.dataset = {};
    this.handlers = {};
    this.textContent = '';
    this.className = '';
    this.disabled = false;
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = [...nodes]; }
  setAttribute(key, value) { this[key] = value; }
  addEventListener(key, handler) { this.handlers[key] = handler; }
}

async function fixture(responses) {
  const nodes = Object.fromEntries(
    ['modules','catalog-status','module-count','connection-status','check-connection']
      .map(id => [id,new Element()]));
  const document = {
    getElementById(id) { assert.ok(nodes[id]); return nodes[id]; },
    createElement() { return new Element(); },
    createDocumentFragment() { return new Element(); },
  };
  const fetch = async (url, options) => {
    assert.equal(options?.credentials, 'omit', 'preview must not send browser credentials');
    if (url === './products.json') return {
      ok:true, text:async()=>JSON.stringify(products),
    };
    if (url === '/api/platform/status') return {
      ok:true,text:async()=>JSON.stringify({
        schema:'forgeworks-portal-status-v1',
        environment:'development',status:'reachable',
      }),
    };
    assert.equal(url,'/api/platform/services');
    const item = responses.shift();
    if (item instanceof Error) throw item;
    assert.ok(item, 'An unexpected extra fleet request occurred');
    return {ok:item.ok,text:async()=>JSON.stringify(item.body)};
  };
  runInNewContext(js, { document, fetch, AbortController, setTimeout, clearTimeout });
  // load() is started as a microtask by the portal script.
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(nodes.modules.children.length,1);
  const labels = () => nodes.modules.children[0].children.map(
    card => card.children.find(child => child.className === 'service-status'));
  const click = () => nodes['check-connection'].handlers.click();
  return {nodes, labels, click};
}

test('PASS cannot survive a subsequent network outage', async () => {
  const ui = await fixture([
    {ok:true,body:fleet()},new Error('Synthetic connection outage'),
  ]);
  await ui.click();
  assert.ok(ui.labels().every(label => label.dataset.state === 'ready'));
  await ui.click();
  assert.ok(ui.labels().every(label => label.dataset.state === 'unavailable'));
  assert.match(ui.nodes['connection-status'].textContent, /gagal/);
  assert.equal(ui.nodes['check-connection'].disabled, false);
});

test('contradictory PASS with unavailable service is never shown as healthy', async () => {
  const ui = await fixture([
    {ok:true,body:fleet()},
    {ok:true,body:fleet('PASS',['specforge-ai'])},
  ]);
  await ui.click();
  await ui.click();
  assert.ok(ui.labels().every(label => label.dataset.state === 'unavailable'));
  assert.doesNotMatch(ui.nodes['connection-status'].textContent, /5\/5 identitas/);
});

test('valid degraded response distinguishes unavailable services', async () => {
  const ui = await fixture([{ok:false,body:fleet('DEGRADED',['agenttest-lab'])}]);
  await ui.click();
  assert.equal(ui.labels()[3].dataset.state,'unavailable');
  assert.ok(ui.labels().filter(label => label.dataset.state === 'ready').length === 4);
  assert.match(ui.nodes['connection-status'].textContent, /tidak terverifikasi/);
});

test('truncated or malformed fleet never leaves green labels', async () => {
  const ui = await fixture([
    {ok:true,body:fleet()},
    {ok:true,body:{...fleet(),services:[]}},
  ]);
  await ui.click();
  await ui.click();
  assert.ok(ui.labels().every(label => label.dataset.state === 'unavailable'));
});
