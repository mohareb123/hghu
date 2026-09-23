'use strict';
(()=>{
  const categories=['AUTH','SESSION','SERVER_DISCOVERY','TRANSPORT','PACKET_CODEC','GAME','ROOM','MATCH','PLAYER','TEAM','FRIEND','GUILD','CHAT','VOICE','ANALYTICS','TELEMETRY','UNKNOWN'];
  let currentPage=0, items=[], botFiles=[], comparing=false;
  for(const category of categories)$('protocol-category').add(new Option(category,category));
  function download(value,name){const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'}));const a=node('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);}
  $('export-protocol').onclick=()=>download(report.protocol_report,'protocol_report.json');
  $('export-graph').onclick=()=>download(report.dependency_graph,'dependency_graph.json');
  function select(item){
    const path=$('protocol-path');path.replaceChildren();
    path.append(node('p','',item.network?'مسار ثابت إلى النقل — لا يثبت أن حقول الرسالة تُرسل خلاله.':'لم يُكتشف مسار نقل لهذا العنصر ضمن التغطية الحالية.'));
    const chain=node('ol','protocol-chain');
    for(const name of item.network_path)chain.append(node('li','',name));
    path.append(chain);
    const ids=new Set([item.id,...item.network_path_node_ids,...(item.method_node_ids||[])]);
    const edges=(report.dependency_graph?.edges||[]).filter(e=>ids.has(e.source)||ids.has(e.target));
    $('protocol-detail').textContent=JSON.stringify({...item,adjacent_edges:edges.slice(0,80),adjacent_edges_omitted:Math.max(0,edges.length-80)},null,2);
  }
  function render(){
    const category=$('protocol-category').value,priority=$('protocol-priority').value,query=$('protocol-search').value.toLowerCase();
    const filtered=items.filter(i=>(category==='ALL'||i.type===category)&&(priority==='ALL'||(priority==='FOCUSED'?i.score>=20:i.priority===priority))&&(!$('protocol-messages-only').checked||i.proto_candidate)&&(!query||[i.name,...i.fields,...i.references].join(' ').toLowerCase().includes(query)));
    const pages=Math.max(1,Math.ceil(filtered.length/25));currentPage=Math.min(currentPage,pages-1);
    $('protocol-items').replaceChildren();
    for(const item of filtered.slice(currentPage*25,(currentPage+1)*25)){
      const button=node('button','finding');
      button.append(node('span','finding-main',item.name),node('span','badge '+item.confidence.toLowerCase(),`${item.score} · ${item.priority} · ${item.confidence}`));
      button.onclick=()=>select(item);$('protocol-items').append(button);
    }
    if(!filtered.length)$('protocol-items').append(node('p','','لا توجد نتائج مطابقة. اختر ALL لإظهار UNKNOWN وIGNORE أيضًا.'));
    $('protocol-page').textContent=`${currentPage+1} / ${pages} · ${filtered.length}`;
    $('protocol-prev').disabled=currentPage===0;$('protocol-next').disabled=currentPage+1>=pages;
  }
  window.renderInvestigation=()=>{
    const data=report?.protocol_report,enabled=data?.meta?.enabled;
    $('investigation-panel').hidden=!enabled;items=[];currentPage=0;
    $('protocol-path').replaceChildren();$('protocol-detail').textContent='اختر عنصرًا لعرض أدلته.';
    botFiles=[];$('bot-files').value=$('bot-folder').value='';
    if(!enabled)return;
    for(const category of categories)items.push(...data[category.toLowerCase()]);
    items.sort((a,b)=>b.score-a.score||a.name.localeCompare(b.name));
    $('protocol-categories').replaceChildren();
    for(const category of categories){const button=node('button','button secondary',`${category}: ${data[category.toLowerCase()].length} / Proto ${data.meta.proto_message_counts?.[category]||0}`);button.onclick=()=>{$('protocol-category').value=category;currentPage=0;render();};$('protocol-categories').append(button);}
    $('investigation-summary').textContent=`${items.length} مرشح · ${report.dependency_graph?.nodes?.length||0} عقدة · ${report.dependency_graph?.edges?.length||0} رابط. العدد الأول مرشحون، وProto تعريفات/مرشحو رسائل لا رسائل مؤكدة على الشبكة. ${data.meta.truncated?'⚠ المخطط جزئي. ':''}${(data.meta.warnings||[]).join(' | ')}`;
    $('bot-results').textContent=JSON.stringify(data.bot_matches||[],null,2);$('bot-status').textContent='المقارنة اختيارية؛ اختر ملفاتك فقط عند الحاجة.';
    render();if(items.length)select(items[0]);
  };
  for(const id of ['protocol-category','protocol-priority','protocol-search','protocol-messages-only'])$(id).addEventListener('input',()=>{currentPage=0;render();});
  $('protocol-prev').onclick=()=>{currentPage--;render();};$('protocol-next').onclick=()=>{currentPage++;render();};
  const allowed=/\.(py|js|ts|java|kt|cs|go|rs|c|h|cpp|proto|smali|json|txt|lua|yaml|ini)$/i;
  for(const id of ['bot-files','bot-folder'])$(id).onchange=()=>{
    const files=[...$(id).files], skipped=files.filter(f=>!allowed.test(f.name));
    botFiles=files.filter(f=>allowed.test(f.name)&&!/(^|\/)(\.git|node_modules|\.venv|venv|build|dist|__pycache__)\//.test(f.webkitRelativePath));
    $(id==='bot-files'?'bot-folder':'bot-files').value='';
    $('bot-status').textContent=`${botFiles.length} ملف مصدر محدد؛ ${skipped.length} امتداد غير مدعوم. لم تبدأ المقارنة بعد.`;
  };
  $('bot-clear').onclick=()=>{
    if(comparing)return;botFiles=[];$('bot-files').value=$('bot-folder').value='';
    if(report?.protocol_report){report.protocol_report.bot_matches=[];report.protocol_report.missing_from_new_version=[];delete report.protocol_report.bot_comparison;reportOrigin=null;}
    $('bot-results').textContent='';$('bot-status').textContent='تم مسح المقارنة.';
  };
  $('bot-compare').onclick=async()=>{
    if(comparing||!report?.protocol_report?.meta?.enabled)return;
    const current=report;comparing=true;$('bot-compare').disabled=true;
    try{
      if(!botFiles.length||botFiles.length>500||botFiles.some(f=>f.size>512*1024)||botFiles.reduce((s,f)=>s+f.size,0)>8*1024**2)throw new Error('اختر 1–500 ملف؛ حتى 512 KiB للملف و8 MiB إجمالًا.');
      $('bot-status').textContent='جارٍ قراءة الملفات ومقارنتها دون تشغيلها…';
      const files=await Promise.all(botFiles.map(async f=>({name:(f.webkitRelativePath||f.name).slice(0,500),text:await f.text()})));
      const body=JSON.stringify({protocol_report:current.protocol_report,files});
      if(new Blob([body]).size>32*1024**2)throw new Error('المقارنة أكبر من حد المتصفح؛ استخدم --bot-project عبر CLI.');
      const result=await responseJSON(await fetch('/api/bot-compare',{method:'POST',headers:{'Content-Type':'application/json'},body}));
      if(report!==current)throw new Error('تغير التقرير أثناء المقارنة؛ أعد المحاولة للتقرير الحالي.');
      Object.assign(current.protocol_report,result);reportOrigin=null;
      $('bot-results').textContent=JSON.stringify(result,null,2);
      $('bot-status').textContent=`${result.bot_matches.length} عنصر مقارَن؛ ${result.missing_from_new_version.length} MISSING ضمن الأدلة المتاحة. نزّل protocol_report.json أو ZIP لحفظ المقارنة؛ لا تُعدل ملفات المشروع تلقائيًا.`;
    }catch(error){$('bot-status').textContent=error.message;}
    finally{comparing=false;$('bot-compare').disabled=false;}
  };
})();
