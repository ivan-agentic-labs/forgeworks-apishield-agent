const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function boot(candidate, saved, trusted = 'https://console.invalid') {
  const source = fs.readFileSync('apps/web/app.js', 'utf8');
  const shield = source.includes('APISHIELD_CONFIG');
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {value:'',dataset:{},options:[],classList:{contains(){return false;},add(){},remove(){},toggle(){}},addEventListener(){},after(){}});
    return elements.get(id);
  }
  const location = {origin:'https://console.invalid',search: candidate ? '?' + (shield ? 'apiBaseUrl' : 'api_base') + '=' + encodeURIComponent(candidate) : ''};
  const calls = [];
  const context = {location, URL, URLSearchParams, Date, Math, crypto:{randomUUID(){return 'synthetic';}},
    window:{location,APISHIELD_CONFIG:{apiBaseUrl:trusted},SPECFORGE_API_BASE:trusted},
    localStorage:{getItem(){return saved;},setItem(){},removeItem(){}},
    document:{getElementById:element,querySelector:element,createElement(){return element('created');}},
    fetch(...args){calls.push(args);throw new Error('Unexpected request during initialization');}};
  vm.runInNewContext(source,context);
  assert.equal(calls.length,0);
  return element(shield ? '#api-base-url' : 'api-base').value;
}

for (const candidate of ['https://attacker.invalid','//attacker.invalid','javascript:alert(1)','https://user:pass@console.invalid','https://console.invalid?redirect=evil','https://console.invalid/#evil']) {
  test('untrusted automatic API override is ignored: ' + candidate, () => {
    assert.equal(boot(candidate,null),'https://console.invalid');
    assert.equal(boot(null,candidate),'https://console.invalid');
  });
}

test('same-origin automatic override is preserved', () => {
  assert.equal(boot('https://console.invalid/api',null),'https://console.invalid/api');
  assert.equal(boot(null,'https://console.invalid/api'),'https://console.invalid/api');
});

test('deployment config defines the trusted API origin', () => {
  assert.equal(boot('https://attacker.invalid',null,'https://api.trusted.invalid'),'https://api.trusted.invalid');
  assert.equal(boot('https://api.trusted.invalid/v1',null,'https://api.trusted.invalid'),'https://api.trusted.invalid/v1');
});
