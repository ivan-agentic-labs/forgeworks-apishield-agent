'use strict';
const ts = require('typescript');
const {createHash} = require('node:crypto');
const METHODS = new Set(['get','post','put','patch','delete','head','options','trace']);
const BUILTIN = '/__apishield_builtin_fetch__.d.ts';
const sha = value => createHash('sha256').update(value).digest('hex');
function reject(code) {throw new Error(code);}
function validUnicode(text) {
  for(let i=0;i<text.length;i++) {
    const c=text.charCodeAt(i);
    if(c>=0xD800&&c<=0xDBFF) {const next=text.charCodeAt(++i);if(!(next>=0xDC00&&next<=0xDFFF)) reject('INPUT_INVALID_UNICODE');}
    else if(c>=0xDC00&&c<=0xDFFF) reject('INPUT_INVALID_UNICODE');
  }
}
function boundedJson(value) {
  const pending=[[value,0]];let count=0;
  while(pending.length) {
    const [item,depth]=pending.pop();if(++count>20000||depth>32) reject('CONTRACT_STRUCTURE_BUDGET_EXCEEDED');
    if(item&&typeof item==='object') for(const key of Object.keys(item)) {validUnicode(key);pending.push([item[key],depth+1]);}
    else if(typeof item==='string') validUnicode(item);
    else if(typeof item==='number'&&!Number.isSafeInteger(item)) reject('CONTRACT_NUMERIC_PROFILE_UNSUPPORTED');
    else if(item!==null&&!['string','number','boolean'].includes(typeof item)) reject('CONTRACT_JSON_INVALID');
  }
  if(Buffer.byteLength(JSON.stringify(value))>1048576) reject('CONTRACT_BYTE_BUDGET_EXCEEDED');
}
function stable(value) {
  if(Array.isArray(value))return '['+value.map(stable).join(',')+']';
  if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+stable(value[key])).join(',')+'}';
  return JSON.stringify(value);
}
function operations(contract) {
  boundedJson(contract);
  if(!contract||!/^3\.1\./.test(contract.openapi)||!contract.paths||Array.isArray(contract.paths)||typeof contract.paths!=='object') reject('CONTRACT_OPENAPI31_REQUIRED');
  const entries=[];
  for(const [path,item] of Object.entries(contract.paths)) {
    if(!item||typeof item!=='object'||Array.isArray(item)) reject('CONTRACT_PATH_ITEM_INVALID');
    for(const [method,op] of Object.entries(item)) {
      if(!METHODS.has(method))continue;
      if(!op||typeof op!=='object'||Array.isArray(op))reject('CONTRACT_OPERATION_INVALID');
      entries.push({path,method,op,common:Object.fromEntries(Object.entries(item).filter(([key])=>!METHODS.has(key)))});
    }
  }
  return entries;
}
function relocationMap(before,after) {
  const old=operations(before),current=operations(after),mappings=new Map(),warnings=[];
  // This profile changes only a literal path. No inferred schema, method or server migration.
  const globals=doc=>Object.fromEntries(Object.entries(doc).filter(([key])=>!['paths','info'].includes(key)));
  if(stable(globals(before))!==stable(globals(after)))return {mappings,warnings:['GLOBAL_CONTRACT_CHANGE_REQUIRES_REVIEW']};
  for(const entry of old) {
    if(current.some(next=>next.path===entry.path&&next.method===entry.method))continue;
    const id=entry.op.operationId;
    if(typeof id!=='string'||!id) {warnings.push('REMOVED_OPERATION_WITHOUT_ID');continue;}
    const previous=old.filter(next=>next.op.operationId===id);
    const candidates=current.filter(next=>next.op.operationId===id);
    if(previous.length!==1||candidates.length!==1) {warnings.push('OPERATION_ID_NOT_UNIQUE');continue;}
    const next=candidates[0];
    if(next.method!==entry.method||stable(entry.op)!==stable(next.op)||stable(entry.common)!==stable(next.common)) {warnings.push('OPERATION_CHANGE_REQUIRES_REVIEW');continue;}
    if(!/^\/[A-Za-z0-9_./~-]*$/.test(entry.path)||!/^\/[A-Za-z0-9_./~-]*$/.test(next.path)||[entry.path,next.path].some(path=>path.startsWith('//')||path.split('/').slice(1).some(part=>part==='.'||part==='..'||part===''))) {
      warnings.push('PATH_PROFILE_UNSUPPORTED');continue;
    }
    mappings.set(entry.method.toUpperCase()+' '+entry.path,{operation_id:id,method:entry.method.toUpperCase(),before_path:entry.path,after_path:next.path});
  }
  return {mappings,warnings};
}
function methodOf(call) {
  if(call.arguments.length===1)return 'GET';
  if(call.arguments.length!==2||!ts.isObjectLiteralExpression(call.arguments[1]))reject('DYNAMIC_FETCH_OPTIONS');
  let method='GET',seen=false;
  for(const property of call.arguments[1].properties) {
    if(!(ts.isPropertyAssignment(property)||ts.isShorthandPropertyAssignment(property)))reject('DYNAMIC_FETCH_OPTIONS');
    const name=property.name;
    if(!(ts.isIdentifier(name)||ts.isStringLiteral(name)))reject('DYNAMIC_FETCH_OPTIONS');
    if(name.text==='__proto__')reject('DYNAMIC_FETCH_OPTIONS');
    if(name.text!=='method')continue;
    if(seen||!ts.isPropertyAssignment(property)||!ts.isStringLiteral(property.initializer))reject('DYNAMIC_FETCH_METHOD');
    seen=true;method=property.initializer.text.toUpperCase();
    if(!METHODS.has(method.toLowerCase()))reject('UNSUPPORTED_FETCH_METHOD');
  }
  return method;
}
function analyze(manifest) {
  if(!manifest||Object.keys(manifest).sort().join(',')!=='after,base_sha,before,head_sha,schema_version,sources'||manifest.schema_version!=='typescript-fetch-path-v1')reject('CALLER_PROFILE_UNSUPPORTED');
  if(!/^[0-9a-f]{40}$/.test(manifest.base_sha)||!/^[0-9a-f]{40}$/.test(manifest.head_sha))reject('IMMUTABLE_REVISIONS_REQUIRED');
  if(!Array.isArray(manifest.sources)||manifest.sources.length<1||manifest.sources.length>50)reject('SOURCE_COUNT_BUDGET_EXCEEDED');
  const {mappings,warnings}=relocationMap(manifest.before,manifest.after);
  const files=new Map();let total=0;
  for(const source of manifest.sources) {
    if(!source||Object.keys(source).sort().join(',')!=='content,path,sha256'||typeof source.path!=='string'||!/^([A-Za-z0-9_-][A-Za-z0-9_.-]*\/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*\.ts$/.test(source.path)||source.path.endsWith('.d.ts')||source.path.length>200||source.path.split('/').some(part=>part==='.'||part==='..'))reject('SOURCE_PATH_INVALID');
    if(typeof source.content!=='string')reject('SOURCE_TEXT_REQUIRED');validUnicode(source.content);
    const bytes=Buffer.byteLength(source.content);total+=bytes;
    if(bytes>131072||total>1048576)reject('SOURCE_BYTE_BUDGET_EXCEEDED');
    if(!/^[0-9a-f]{64}$/.test(source.sha256)||sha(source.content)!==source.sha256)reject('SOURCE_DIGEST_MISMATCH');
    const name='/source/'+source.path;if(files.has(name))reject('SOURCE_PATH_DUPLICATE');
    const file=ts.createSourceFile(name,source.content,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS);
    if(file.parseDiagnostics.length)reject('SOURCE_TYPESCRIPT_SYNTAX_INVALID');
    files.set(name,file);
  }
  files.set(BUILTIN,ts.createSourceFile(BUILTIN,'declare function fetch(input: string, options?: unknown): unknown;',ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS));
  const host={getSourceFile:name=>files.get(name),getDefaultLibFileName:()=>BUILTIN,writeFile:()=>reject('EMIT_DISABLED'),getCurrentDirectory:()=>'/source',getDirectories:()=>[],fileExists:name=>files.has(name),readFile:name=>files.get(name)?.text,getCanonicalFileName:name=>name,useCaseSensitiveFileNames:()=>true,getNewLine:()=> '\n'};
  let rebinding=false;
  const namedFetch=node=>ts.isIdentifier(node)&&node.text==='fetch'||ts.isPropertyAccessExpression(node)&&node.name.text==='fetch'||ts.isElementAccessExpression(node)&&ts.isStringLiteral(node.argumentExpression)&&node.argumentExpression.text==='fetch';
  for(const [name,file] of files) {
    if(name===BUILTIN)continue;
    const pending=[file];let visited=0;
    while(pending.length) {
      const node=pending.pop();if(++visited>100000)reject('SOURCE_AST_BUDGET_EXCEEDED');
      ts.forEachChild(node,child=>{pending.push(child);});
      if(ts.isBinaryExpression(node)&&node.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&node.operatorToken.kind<=ts.SyntaxKind.LastAssignment&&namedFetch(node.left))rebinding=true;
      if(ts.isDeleteExpression(node)&&namedFetch(node.expression))rebinding=true;
    }
  }
  const program=ts.createProgram([...files.keys()],{noLib:true,noResolve:true,noEmit:true,target:ts.ScriptTarget.ES2022},host);
  const checker=program.getTypeChecker();const findings=[],proposals=[];let nodes=0;
  for(const [name,file] of files) {
    if(name===BUILTIN)continue;
    const edits=[],pending=[file];
    while(pending.length) {
      const node=pending.pop();if(++nodes>100000)reject('SOURCE_AST_BUDGET_EXCEEDED');
      ts.forEachChild(node,child=>{pending.push(child);});
      if(!ts.isCallExpression(node))continue;
      const expression=node.expression;
      const candidate=ts.isIdentifier(expression)&&expression.text==='fetch';
      const otherFetch=ts.isPropertyAccessExpression(expression)&&expression.name.text==='fetch';
      if(!candidate&&!otherFetch)continue;
      const position=file.getLineAndCharacterOfPosition(node.getStart(file));
      const finding={source_path:name.slice(8),line:position.line+1,column:position.character+1,coverage:'REVIEW_LIMITED'};
      try {
        if(!candidate||node.questionDotToken)reject('CALLER_FORM_UNSUPPORTED');
        if(rebinding)reject('FETCH_RUNTIME_REBINDING');
        const symbol=checker.getSymbolAtLocation(expression);
        if(!symbol?.declarations?.length||symbol.declarations.some(declaration=>declaration.getSourceFile().fileName!==BUILTIN))reject('FETCH_SHADOWED_OR_UNRESOLVED');
        const argument=node.arguments[0];
        if(!argument||!(ts.isStringLiteral(argument)||ts.isNoSubstitutionTemplateLiteral(argument)))reject('DYNAMIC_FETCH_URL');
        const url=argument.text;
        if(!/^\/(?!\/)[A-Za-z0-9_./~?-][A-Za-z0-9_./~?=&%-]*$/.test(url)||url.includes('#')||url.split('?')[0].split('/').some(part=>part==='.'||part==='..'))reject('FETCH_URL_PROFILE_UNSUPPORTED');
        const method=methodOf(node),separator=url.indexOf('?'),path=separator<0?url:url.slice(0,separator);
        const migration=mappings.get(method+' '+path);
        if(!migration) {findings.push({...finding,reason:'NO_SUPPORTED_RELOCATION',method,path});continue;}
        const suffix=separator<0?'':url.slice(separator);
        const edit={start:argument.getStart(file),end:argument.getEnd(),replacement:JSON.stringify(migration.after_path+suffix),...migration};
        edits.push(edit);findings.push({...finding,...migration,reason:'DECLARED_OPERATION_PATH_RELOCATION',coverage:'SUPPORTED_PROFILE'});
      } catch(error) {findings.push({...finding,reason:error.message});}
    }
    if(edits.length) {
      edits.sort((a,b)=>b.start-a.start);let patched=file.text;
      for(const edit of edits)patched=patched.slice(0,edit.start)+edit.replacement+patched.slice(edit.end);
      if(ts.createSourceFile(name,patched,ts.ScriptTarget.ES2022,true,ts.ScriptKind.TS).parseDiagnostics.length)reject('PATCH_TYPESCRIPT_SYNTAX_INVALID');
      proposals.push({source_path:name.slice(8),before_sha256:sha(file.text),after_sha256:sha(patched),patched_content:patched,edits});
    }
  }
  findings.sort((a,b)=>a.source_path.localeCompare(b.source_path)||a.line-b.line||a.column-b.column);
  return {schema_version:manifest.schema_version,base_sha:manifest.base_sha,head_sha:manifest.head_sha,
    contract_before_canonical_sha256:sha(stable(manifest.before)),contract_after_canonical_sha256:sha(stable(manifest.after)),
    parser_version:ts.version,analysis_status:'LIMITED_PROFILE',patch_kind:'TYPESCRIPT_FETCH_PATH',
    sandbox_status:'NOT_RUN',approval_status:'PENDING',warnings:[...new Set(warnings)],findings,proposals};
}
function parseManifestJson(bytes) {
  if(bytes.length>4194304)reject('CALLER_INPUT_BUDGET_EXCEEDED');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),stack=[];
  for(let i=0;i<text.length;i++) {
    const c=text[i];
    if(c==='"') {
      const start=i;
      while(++i<text.length) {if(text[i]==='\\')i++;else if(text[i]==='"')break;}
      let next=i+1;while(/\s/.test(text[next]||'x'))next++;
      if(text[next]===':'&&stack.at(-1)?.keys) {
        const key=JSON.parse(text.slice(start,i+1)),keys=stack.at(-1).keys;
        if(keys.has(key))reject('CALLER_DUPLICATE_JSON_KEY');keys.add(key);
      }
    } else if(c==='-'||/[0-9]/.test(c)) {
      let end=i+1;while(/[0-9.eE+-]/.test(text[end]||'x'))end++;
      const number=text.slice(i,end);
      if(!/^-?(0|[1-9][0-9]*)$/.test(number)||!Number.isSafeInteger(Number(number)))reject('CONTRACT_NUMERIC_PROFILE_UNSUPPORTED');
      i=end-1;
    } else if(c==='{'||c==='[') {
      if(stack.length>=64)reject('CALLER_STRUCTURE_BUDGET_EXCEEDED');
      stack.push({keys:c==='{'?new Set():null});
    } else if(c==='}'||c===']')stack.pop();
  }
  return JSON.parse(text);
}
module.exports={analyze,sha,parseManifestJson};
if(require.main===module) {
  const chunks=[];let bytes=0;
  process.stdin.on('data',chunk=>{bytes+=chunk.length;if(bytes>4194304){process.stderr.write('CALLER_INPUT_BUDGET_EXCEEDED\n');process.exit(1);}chunks.push(chunk);});
  process.stdin.on('end',()=>{try{const result=analyze(parseManifestJson(Buffer.concat(chunks)));process.stdout.write(JSON.stringify(result));}catch(_){process.stderr.write('CALLER_ANALYSIS_REJECTED\n');process.exitCode=1;}});
}
