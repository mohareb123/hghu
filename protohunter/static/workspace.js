'use strict';
(()=>{
  let project=null, opened=null, files=[], job=null, working=false, capabilities=null;
  const byId=id=>document.getElementById(id);
  const say=(text,error=false)=>{byId('ws-message').textContent=text;byId('ws-message').className=error?'error':'';};
  const api=(action,body={})=>desktopRequest('/api/workspace',{action,project:project?.id,...body});
  const dirty=()=>opened?.editable && byId('ws-code').value!==opened.editorText;
  const discard=()=>!dirty() || window.confirm('توجد تعديلات غير محفوظة. تجاهلها؟');
  function controls(value){
    working=value;setBusy(value);byId('cancel-job').disabled=!activeJob;
    document.querySelectorAll('#workspace-controls button,#workspace-controls select,#workspace-controls input').forEach(el=>el.disabled=value);
    byId('ws-create').disabled=value || !capabilities?.native_picker;
    byId('ws-folder').disabled=value || !project || !capabilities?.native_picker;
    byId('ws-pick-key').disabled=value || !capabilities?.native_picker;
    byId('ws-cancel').disabled=!job;
    byId('ws-code').readOnly=value || !opened?.editable;
    for(const id of ['ws-save','ws-diff'])byId(id).disabled=value || !opened?.editable;
    byId('ws-restore').disabled=value || !opened?.editable || !project?.changes.some(c=>c.path===opened.path);
    document.querySelectorAll('[data-operation]').forEach(el=>el.disabled=value || !project || !capabilities?.allow_decoders);
  }
  async function action(callback){
    if(busy || working || activeJob)return say('انتظر المهمة الحالية أو ألغها أولًا.',true);
    controls(true);
    try{await callback();}catch(error){say(error.message,true);}finally{controls(false);}
  }
  async function refresh(){
    const result=await api('list');
    byId('ws-project').replaceChildren(new Option('اختر مشروعًا',''),...result.projects.map(p=>new Option(p.name+' · '+p.id.slice(0,8),p.id)));
    if(project)byId('ws-project').value=project.id;
  }
  function drawFiles(entries=files){
    const filter=byId('ws-filter').value.toLowerCase();
    const list=entries.filter(file=>file.path.toLowerCase().includes(filter));
    byId('ws-file-count').textContent=`${list.length} نتيجة · عرض أول 300 · استخدم التصفية/البحث`;
    byId('ws-files').replaceChildren(...list.slice(0,300).map(file=>{
      const button=document.createElement('button');button.className='ws-file';button.dir='ltr';
      button.textContent=file.path+(file.line?':'+file.line+' — '+file.text:'');
      button.addEventListener('click',()=>action(async()=>{if(discard())await open(file.path,file.line);}));return button;
    }));
  }
  async function open(path,line){
    opened=await api('read',{path});byId('ws-file-title').textContent=path;
    byId('ws-code').value=opened.binary?'ملف ثنائي — استخدم «فتح مجلد المشروع» للوصول إليه.':opened.text;
    opened.editorText=byId('ws-code').value;
    byId('ws-readonly').textContent=opened.editable?'قابل للتعديل · نسخة احتياطية عند الحفظ':opened.truncated?'معاينة أول 1 MiB فقط · للقراءة':'للقراءة فقط';
    byId('ws-diff-text').hidden=true;
    if(line){const offset=opened.text.split('\n').slice(0,line-1).join('\n').length;byId('ws-code').focus();byId('ws-code').setSelectionRange(offset,offset);byId('ws-code').scrollTop=(line-1)*20;}
  }
  async function loadProject(id){
    project=await api('get',{project:id});opened=null;byId('ws-code').value='';byId('ws-file-title').textContent='اختر ملفًا';
    byId('ws-unit').replaceChildren(...project.units.map(u=>new Option(u.name+' · '+u.id,u.id)));
    byId('ws-binary').replaceChildren();byId('ws-metadata').replaceChildren();
    await updateFiles();await refresh();
    say(`المشروع ${project.name} · ${project.units.length} وحدة APK · بصمة الأصل ${project.input.sha256.slice(0,16)}…`);
  }
  async function updateFiles(){
    project=await api('get');const result=await api('files');files=result.files;drawFiles();
    byId('ws-history').replaceChildren(...[...project.runs].reverse().map(run=>{
      const item=document.createElement('p');item.dir='ltr';item.textContent=`${run.operation} / ${run.unit} · ${run.status} · ${run.path}${run.error?' · '+run.error:''}${run.note?' · '+run.note:''}`;return item;
    }));
    if(result.truncated)say('قائمة الملفات تجاوزت 20,000 ملف؛ المعروض جزئي.',true);
  }
  async function follow(accepted){
    if(accepted.cancelled)return null;
    job=accepted.job_id;byId('ws-cancel').disabled=false;byId('ws-progress').hidden=false;byId('ws-log').hidden=false;
    try{
      for(;;){
        const state=await responseJSON(await fetch('/api/jobs/'+job,{headers:{'X-ProtoHunter-Config-Token':desktopToken}}));
        say(`${state.progress.stage} · ${state.elapsed_seconds} ثانية · ${state.status}`);
        if(state.progress.log)byId('ws-log').textContent=state.progress.log;
        if(state.status==='completed')return responseJSON(await fetch('/api/jobs/'+job+'/result',{headers:{'X-ProtoHunter-Config-Token':desktopToken}}));
        if(state.status==='failed' || state.status==='cancelled')throw new Error(state.error || 'أُلغيت العملية. المخرجات الجزئية محفوظة وسجلها يوضح حالتها.');
        await new Promise(resolve=>setTimeout(resolve,750));
      }
    }catch(error){
      // Do not orphan a long-running decoder after losing its status connection.
      await fetch('/api/jobs/'+job+'/cancel',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-ProtoHunter-Config-Token':desktopToken},body:new Uint8Array()}).catch(()=>{});
      throw error;
    }finally{job=null;byId('ws-cancel').disabled=true;byId('ws-progress').hidden=true;}
  }
  byId('ws-refresh').addEventListener('click',()=>action(refresh));
  byId('ws-create').addEventListener('click',()=>action(async()=>{
    if(!discard())return;
    say('اختر الحزمة من نافذة Windows. سيُحفظ أصل مستقل داخل المشروع.');
    const result=await follow(await api('create'));if(result)await loadProject(result.id);
  }));
  byId('ws-project').addEventListener('change',()=>action(async()=>{
    const id=byId('ws-project').value;
    if(!discard()){byId('ws-project').value=project?.id || '';return;}
    if(id)await loadProject(id);
  }));
  byId('ws-folder').addEventListener('click',()=>action(()=>api('open-folder')));
  byId('ws-filter').addEventListener('input',()=>drawFiles());
  byId('ws-search').addEventListener('click',()=>action(async()=>{
    if(!project)throw new Error('اختر مشروعًا أولًا');
    const result=await api('search',{query:byId('ws-query').value});drawFiles(result.hits);
    say(`${result.hits.length} تطابق · ${result.scanned} ملف · ${result.truncated?'بحث جزئي بسبب الحدود؛ ليس دليل غياب':'انتهى البحث'} · ${result.skipped} ملف كبير متخطّى`);
  }));
  byId('ws-discover').addEventListener('click',()=>action(async()=>{
    const result=await api('candidates');
    for(const [id,key] of [['ws-binary','binaries'],['ws-metadata','metadata']])byId(id).replaceChildren(...result[key].map(x=>new Option(`${x.unit} / ${x.member}`,JSON.stringify({unit:x.unit,member:x.member}))));
    say(`${result.binaries.length} مكتبة و${result.metadata.length} metadata. راجع المعمارية والزوج قبل التشغيل.`);
  }));
  byId('ws-pick-key').addEventListener('click',()=>action(async()=>{const result=await api('choose-keystore');if(result.path)byId('ws-keystore').value=result.path;}));
  document.querySelectorAll('[data-operation]').forEach(button=>button.addEventListener('click',()=>action(async()=>{
    if(dirty())throw new Error('احفظ تعديلات المحرر أو أعد فتح الملف قبل تشغيل المحركات.');
    const operation=button.dataset.operation,unit=byId('ws-unit').value;let options={};
    if(operation==='apktool' && project.decoded[unit] && !window.confirm('سيتم فك نسخة جديدة من الأصل وجعلها نسخة التعديل الحالية. النسخة المعدلة القديمة ستبقى محفوظة في سجل التشغيل. متابعة؟'))return;
    if(operation==='il2cpp'){
      if(!byId('ws-binary').value || !byId('ws-metadata').value)throw new Error('اكتشف ملفات Unity واختر المكتبة والـmetadata أولًا.');
      options={binary:JSON.parse(byId('ws-binary').value),metadata:JSON.parse(byId('ws-metadata').value)};
    }
    if(operation==='sign'){
      options={keystore:byId('ws-keystore').value,alias:byId('ws-alias').value,store_pass:byId('ws-store-pass').value,key_pass:byId('ws-key-pass').value};
      byId('ws-store-pass').value=byId('ws-key-pass').value='';
    }
    let failure;
    try{await follow(await api('run',{operation,unit,options}));}catch(error){failure=error;}
    await updateFiles();
    if(opened && !dirty())await open(opened.path);
    if(failure)throw failure;
    if(operation==='inspect')showReport(await api('report',{unit}));
    say('اكتملت العملية. الملفات والسجل محفوظان؛ استخدم «فتح مجلد المشروع» للوصول إلى APK والمخرجات.');
  })));
  for(const actionName of ['diff','save'])byId('ws-'+actionName).addEventListener('click',()=>action(async()=>{
    const result=await api(actionName,{path:opened.path,text:byId('ws-code').value,sha256:opened.sha256});
    if(actionName==='diff'){byId('ws-diff-text').textContent=(result.diff || 'لا توجد تغييرات')+(result.truncated?'\n… فرق جزئي':'');byId('ws-diff-text').hidden=false;}
    else{await updateFiles();await open(result.path);say('تم الحفظ مع نسخة احتياطية. يلزم إعادة البناء ثم التوقيع لتطبيق التعديلات.');}
  }));
  byId('ws-restore').addEventListener('click',()=>action(async()=>{
    if(!discard())return;
    const edit=[...project.changes].reverse().find(c=>c.path===opened.path);
    if(!edit)throw new Error('لا توجد نسخة احتياطية لهذا الملف');
    const result=await api('restore',{edit:edit.id,sha256:opened.sha256});await updateFiles();await open(result.path);say('تمت الاستعادة؛ العملية نفسها مسجلة في تاريخ التعديلات.');
  }));
  byId('ws-cancel').addEventListener('click',async()=>{
    if(!job)return;
    try{await responseJSON(await fetch('/api/jobs/'+job+'/cancel',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-ProtoHunter-Config-Token':desktopToken},body:new Uint8Array()}));say('طلب إلغاء؛ انتظر توقف المحرك.');}catch(error){say(error.message,true);}
  });
  function initialize(status){
    capabilities=status;byId('workspace-controls').hidden=!status.desktop_tools;byId('ws-local-notice').hidden=status.desktop_tools;
    if(status.desktop_tools && !working && !busy){refresh().catch(e=>say(e.message,true));controls(false);}
  }
  document.addEventListener('protohunter-status',event=>initialize(event.detail));
  if(serverStatus)initialize(serverStatus);
  window.addEventListener('beforeunload',event=>{if(dirty() || job){event.preventDefault();event.returnValue='';}});
})();
