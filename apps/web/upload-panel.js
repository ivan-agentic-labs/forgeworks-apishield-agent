(() => {
  'use strict';
  const product=document.body.dataset.forgeProduct;
  if(!['specforge-ai','datareconcile-ai','agenttest-lab','apishield-agent'].includes(product))return;
  const panel=document.createElement('section');panel.className='panel card';
  panel.innerHTML='<h2>Unggah berkas sumber</h2><form id="forge-upload-form"><label>Berkas<input id="forge-source-file" type="file" required></label>'+(product==='specforge-ai'?'<label>Judul kebutuhan<input id="forge-source-title" value="Kebutuhan API" required maxlength="200"></label>':'')+'<button type="submit" id="forge-upload-button">Unggah dan validasi</button></form><p id="forge-upload-status" role="status" aria-live="polite">Pilih berkas yang akan dipakai dalam alur aplikasi.</p>';
  const main=document.querySelector('main')||document.body;main.insertBefore(panel,main.children[2]||null);
  const $=id=>document.getElementById(id);const status=text=>{$('forge-upload-status').textContent=text;};
  const digest=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))).map(x=>x.toString(16).padStart(2,'0')).join('');
  function headers(){const input=$('token')||$('bearer-token');const value=input?.value.trim();if(!value)throw new Error('Masuk terlebih dahulu sebelum mengunggah.');return {'Authorization':'Bearer '+value,'Content-Type':'application/json','Idempotency-Key':'upload-'+crypto.randomUUID()};}
  async function command(path,body){const response=await fetch(path,{method:'POST',headers:headers(),body:JSON.stringify(body),cache:'no-store'});const value=await response.json().catch(()=>({}));if(!response.ok)throw new Error(value.detail||'Permintaan gagal ('+response.status+').');return value;}
  window.addEventListener('forge-session-cleared',()=>{delete window.forgeUploadedArtifact;$('forge-source-file').value='';status('Sesi ditutup. Masuk kembali sebelum mengunggah.');});
  $('forge-upload-form').addEventListener('submit',async event=>{
    event.preventDefault();const button=$('forge-upload-button');button.disabled=true;
    try{
      const file=$('forge-source-file').files[0];const limit=product==='apishield-agent'?2097152:1048576;if(!file||file.size<1||file.size>limit)throw new Error('Ukuran berkas harus 1 byte sampai '+limit+' byte.');
      headers();const bytes=await file.arrayBuffer(),sha256=await digest(bytes);
      const kind=product==='agenttest-lab'?'dataset':product==='apishield-agent'?'contract':'source';
      const media=product==='agenttest-lab'?'application/x-ndjson':product==='datareconcile-ai'?'text/csv':product==='apishield-agent'?'application/yaml':'text/plain';
      status('Mengunggah dan memeriksa integritas berkas…');
      const intent=await command('/v1/artifacts/upload-intents',{kind,filename:file.name,size_bytes:file.size,sha256,declared_media_type:media});
      const url=new URL(intent.upload_url,location.origin);if(url.origin!==location.origin||!url.pathname.startsWith('/v1/artifact-transfers/'))throw new Error('Alamat unggah tidak valid.');
      const response=await fetch(url,{method:'PUT',headers:intent.required_headers||{},body:bytes,cache:'no-store'});const uploaded=await response.json();if(!response.ok)throw new Error(uploaded.detail||'Unggah gagal.');
      const committed=await command('/v1/artifacts/'+intent.artifact_id+'/commit',{sha256,size_bytes:file.size,object_generation:uploaded.object_generation});
      if(committed.status!=='AVAILABLE')throw new Error('Berkas belum tersedia setelah validasi.');
      const result={artifact_id:intent.artifact_id,sha256,size_bytes:file.size};
      if(product==='agenttest-lab'){
        result.caseKeys=new TextDecoder('utf-8',{fatal:true}).decode(bytes).split(/\r?\n/).filter(line=>line.trim()).map(line=>JSON.parse(line).case_key);
        $('artifact-id').value=result.artifact_id;
      }
      if(product==='datareconcile-ai'){$('artifactId').value=result.artifact_id;$('fileSha').value=sha256;$('csvContent').value='';}
      if(product==='specforge-ai'){
        const set=await command('/v1/requirement-sets',{title:$('forge-source-title').value.trim(),source_artifact_id:result.artifact_id,source_sha256:sha256});
        $('set-id').value=set.id;$('load-btn').click();
      }
      window.forgeUploadedArtifact=result;window.dispatchEvent(new CustomEvent('forge-artifact-ready',{detail:result}));
      status('Berkas tersedia dan siap dipakai. ID: '+result.artifact_id);
    }catch(error){status(error.message);}finally{button.disabled=false;}
  });
})();
