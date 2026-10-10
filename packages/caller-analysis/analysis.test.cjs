'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {analyze,sha,parseManifestJson}=require('./analysis.cjs');
function manifest(content='fetch("/old");',method='get') {
  const op={operationId:'listItems',responses:{'200':{description:'List items'}}};
  return {schema_version:'typescript-fetch-path-v1',base_sha:'a'.repeat(40),head_sha:'b'.repeat(40),
    before:{openapi:'3.1.0',info:{title:'API',version:'1'},paths:{'/old':{[method]:op}}},
    after:{openapi:'3.1.0',info:{title:'API',version:'2'},paths:{'/new':{[method]:structuredClone(op)}}},
    sources:[{path:'src/client.ts',content,sha256:sha(content)}]};
}
function run(source,method){return analyze(manifest(source,method));}

test('actual TypeScript AST maps and proposes a literal global fetch path migration',()=>{
  const result=run('export async function items(): Promise<unknown> { return fetch("/old"); }');
  assert.equal(result.proposals.length,1);assert.match(result.proposals[0].patched_content,/fetch\("\/new"\)/);
  assert.equal(result.findings[0].operation_id,'listItems');assert.equal(result.findings[0].line,1);
  assert.equal(result.proposals[0].after_sha256,sha(result.proposals[0].patched_content));
  assert.equal(result.sandbox_status,'NOT_RUN');assert.equal(result.approval_status,'PENDING');
});

test('query bytes and unrelated source text survive migration',()=>{
  const content="// source stays\nconst result = fetch('/old?limit=2&cursor=x%2Fy');\nconst unrelated = '/old';\n";
  const result=run(content),patched=result.proposals[0].patched_content;
  assert.equal(patched,"// source stays\nconst result = fetch(\"/new?limit=2&cursor=x%2Fy\");\nconst unrelated = '/old';\n");
  assert.equal(result.findings[0].line,2);
});

test('several edits retain correct source offsets',()=>{
  const result=run('fetch("/old"); fetch(`/old`);');
  assert.equal(result.proposals[0].patched_content,'fetch("/new"); fetch("/new");');
  assert.equal(result.proposals[0].edits.length,2);
});

test('literal POST options use the declared HTTP operation',()=>{
  const result=run('fetch("/old", {method: "post", body: "{}"});','post');
  assert.equal(result.proposals.length,1);assert.equal(result.findings[0].method,'POST');
});

for(const content of [
  'function f(fetch: Function) { return fetch("/old"); }',
  'const fetch = (url: string) => url; fetch("/old");',
  'import fetch from "other-library"; fetch("/old");',
])test('shadowed fetch produces no patch: '+content,()=>{
  const result=run(content);assert.equal(result.proposals.length,0);
  assert.equal(result.findings[0].reason,'FETCH_SHADOWED_OR_UNRESOLVED');
});

test('comments and string contents are not callers',()=>{
  const result=run('// fetch("/old")\nconst example = \'fetch("/old")\';');
  assert.equal(result.findings.length,0);assert.equal(result.proposals.length,0);
});

test('source is parsed as data, never executed',()=>{
  const result=run('throw new Error("must never execute"); fetch("/old");');
  assert.equal(result.proposals.length,1);
});

for(const [content,reason] of [
  ['fetch(url);','DYNAMIC_FETCH_URL'],
  ['fetch(`/old/${id}`);','DYNAMIC_FETCH_URL'],
  ['fetch("/old", options);','DYNAMIC_FETCH_OPTIONS'],
  ['fetch("/old", {...options});','DYNAMIC_FETCH_OPTIONS'],
  ['fetch("/old", {method: verb});','DYNAMIC_FETCH_METHOD'],
  ['fetch("/old", {method:"GET",method:"POST"});','DYNAMIC_FETCH_METHOD'],
  ['fetch("/old", {__proto__:options});','DYNAMIC_FETCH_OPTIONS'],
  ['fetch("/old", {[key]:"POST"});','DYNAMIC_FETCH_OPTIONS'],
  ['globalThis.fetch("/old");','CALLER_FORM_UNSUPPORTED'],
  ['fetch?.("/old");','CALLER_FORM_UNSUPPORTED'],
  ['fetch("https://api.example.invalid/old");','FETCH_URL_PROFILE_UNSUPPORTED'],
  ['fetch("//api.example.invalid/old");','FETCH_URL_PROFILE_UNSUPPORTED'],
  ['fetch("/x/../old");','FETCH_URL_PROFILE_UNSUPPORTED'],
])test('unsupported caller remains review-only: '+content,()=>{
  const result=run(content);assert.equal(result.proposals.length,0);assert.equal(result.findings[0].reason,reason);
});

test('global changes never silently become path-only migrations',()=>{
  const value=manifest();value.after.servers=[{url:'https://api.example.invalid'}];
  const result=analyze(value);assert.equal(result.proposals.length,0);
  assert.deepEqual(result.warnings,['GLOBAL_CONTRACT_CHANGE_REQUIRES_REVIEW']);
});

test('operation schema changes require review',()=>{
  const value=manifest();value.after.paths['/new'].get.responses['201']={description:'Created'};
  const result=analyze(value);assert.equal(result.proposals.length,0);assert.ok(result.warnings.includes('OPERATION_CHANGE_REQUIRES_REVIEW'));
});

test('duplicate operation identity cannot choose a destination',()=>{
  const value=manifest();value.after.paths['/other']=structuredClone(value.after.paths['/new']);
  const result=analyze(value);assert.equal(result.proposals.length,0);assert.ok(result.warnings.includes('OPERATION_ID_NOT_UNIQUE'));
});

test('still-supported old endpoint is not rewritten',()=>{
  const value=manifest();value.after.paths['/old']=structuredClone(value.before.paths['/old']);
  assert.equal(analyze(value).proposals.length,0);
});

for(const [change,code] of [
  [v=>v.sources[0].sha256='0'.repeat(64),'SOURCE_DIGEST_MISMATCH'],
  [v=>v.sources[0].path='../client.ts','SOURCE_PATH_INVALID'],
  [v=>v.sources[0].path='src/client.tsx','SOURCE_PATH_INVALID'],
  [v=>v.sources.push(v.sources[0]),'SOURCE_PATH_DUPLICATE'],
  [v=>v.sources=[],'SOURCE_COUNT_BUDGET_EXCEEDED'],
  [v=>v.base_sha='main','IMMUTABLE_REVISIONS_REQUIRED'],
  [v=>v.schema_version='all-typescript','CALLER_PROFILE_UNSUPPORTED'],
  [v=>{v.sources[0].content='fetch(';v.sources[0].sha256=sha('fetch(');},'SOURCE_TYPESCRIPT_SYNTAX_INVALID'],
  [v=>{v.sources[0].content='x'.repeat(131073);v.sources[0].sha256=sha(v.sources[0].content);},'SOURCE_BYTE_BUDGET_EXCEEDED'],
])test('invalid caller manifest fails closed: '+code,()=>{
  const value=manifest();change(value);assert.throws(()=>analyze(value),new RegExp(code));
});

test('strict JSON bridge rejects duplicate keys and invalid UTF8',()=>{
  assert.throws(()=>parseManifestJson(Buffer.from('{"before":1,"before":2}')),/CALLER_DUPLICATE_JSON_KEY/);
  assert.throws(()=>parseManifestJson(Buffer.from([0xff])));
  assert.throws(()=>parseManifestJson(Buffer.from('{"a":1,"\\u0061":2}')),/CALLER_DUPLICATE_JSON_KEY/);
  assert.deepEqual(parseManifestJson(Buffer.from('{"text":"{\\\"a\\\":1}","other":2}')),{text:'{"a":1}',other:2});
});

for(const source of ['fetch = replacement; fetch("/old");','globalThis.fetch = replacement; fetch("/old");','delete globalThis["fetch"]; fetch("/old");']) {
  test('direct runtime fetch rebinding is review-only: '+source,()=>{
    const result=run(source);assert.equal(result.proposals.length,0);
    assert.equal(result.findings[0].reason,'FETCH_RUNTIME_REBINDING');
  });
}

for(const number of ['9007199254740993','1.0000000000000001','1e0']) {
  test('numeric precision outside the narrow profile is rejected: '+number,()=>{
    assert.throws(()=>parseManifestJson(Buffer.from('{"limit":'+number+'}')),/CONTRACT_NUMERIC_PROFILE_UNSUPPORTED/);
  });
}
