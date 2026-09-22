'use strict';
const $ = id => document.getElementById(id);
const titles = {research:'Login → Session → Game', flow:'مراجع الاستدعاءات — ليست تتبع تشغيل', coverage:'سجل التغطية والملفات المتخطاة', endpoints:'السيرفرات والروابط', protocols:'بروتوكولات الاتصال', protobuf:'Protobuf وgRPC', smali:'فهرس Smali', servers:'تجميع أدلة السيرفرات', native:'Native وUnity/IL2CPP', bundles:'الحزم وSplit APK', sources:'ملفات المصدر'};
const confidenceLabels = {high:'عالية', medium:'متوسطة', low:'محتمل'};
let report = null, view = 'endpoints', page = 0, selected = null, busy = false, copyText = '';
const pageSize = 30;
const stageLabels={login:'Login / إعدادات',session:'بيانات الجلسة',transport:'TCP / اتصال',messages:'رسائل اللعبة',security:'التشفير والمصادقة',serialization:'Serialization',discovery:'الشبكات'};
function node(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}
function notice(text, error = false) {
  $('notification').textContent = text;
  $('notification').className = 'notification' + (error ? ' error' : '');
  $('notification').hidden = !text;
}
function setBusy(value) {
  busy = value;
  $('choose').disabled = $('demo').disabled = $('decoder').disabled = $('profile').disabled = value;
  $('dropzone').classList.toggle('busy', value);
  $('choose').textContent = value ? 'جارٍ التحليل…' : '+ اختر ملفًا';
}
async function load(file, demo = false) {
  if (busy) return;
  if (!demo && !file) return;
  const limit = $('profile').value === 'games' ? 2 * 1024**3 : 128 * 1024**2;
  if (file && file.size > limit) return notice('الملف أكبر من حد الوضع المحدد. للحزم الضخمة استخدم CLI أو حلّل مجلد الملفات.', true);
  setBusy(true);
  notice('جارٍ رفع الملف وتحليله على الخادم المحلي. فك الكود الخارجي قد يستغرق عدة دقائق.');
  try {
    const params = new URLSearchParams({name: demo ? 'demo.smali' : file.name, decode: demo ? 'none' : $('decoder').value, profile:$('profile').value});
    const response = await fetch(`${demo ? '/api/demo' : '/api/analyze'}?${params}`, {
      method:'POST', headers:{'Content-Type':'application/octet-stream'}, body:demo ? new Uint8Array() : file
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'تعذّر تحليل الملف');
    report = data; page = 0; selected = null; copyText = '';
    $('copy').disabled = false;
    $('export').disabled = false;
    $('search').value = ''; $('confidence').value = 'all'; $('relevance-filter').value='all'; $('stage-filter').value='all';
    $('upload-title').textContent = data.input.name;
    $('upload-description').textContent = demo ? 'مثال صناعي للتجربة فقط — العناوين ليست سيرفرات حقيقية.' : 'اكتمل التحليل. اختر نتيجة لفحص الدليل، أو ارفع ملفًا آخر.';
    const summary = data.summary;
    $('stat-endpoints').textContent = summary.unique_endpoints;
    $('stat-protocols').textContent = summary.protocols;
    $('stat-protobuf').textContent = summary.protobuf_findings;
    $('stat-smali').textContent = summary.smali_classes;
    $('stat-native').textContent = summary.native_modules;
    $('stat-bundles').textContent = summary.bundle_findings;
    $('stat-servers').textContent = summary.unique_hosts;
    for (const key of Object.keys(titles)) $('count-' + key).textContent = data[key].length;
    $('report-meta').textContent = `${data.input.name} · ${summary.files_scanned} ملف · ${summary.elapsed_seconds} ثانية`;
    renderResearchOverview();
    const warnings = [...data.warnings, ...data.limitations];
    $('warnings').replaceChildren(...warnings.map(text => node('li', '', text)));
    $('warnings-box').hidden = false;
    $('warnings-title').textContent = `حدود التحليل وملاحظاته (${warnings.length})`;
    notice(demo ? 'تقرير تجريبي من ملف Smali صناعي. كل النتائج مستخرجة فعليًا من الملف.' : `اكتمل التحليل: ${summary.findings} نتيجة عامة و${summary.research_findings} مؤشر في خطة البحث. ${data.warnings.length ? 'راجع ملاحظات التحليل أدناه.' : ''}`);
    render();
  } catch (error) {
    notice('تعذّر إكمال التحليل: ' + error.message, true);
  } finally { setBusy(false); $('file-input').value = ''; }
}
function rows() {
  if (!report) return [];
  const query = $('search').value.trim().toLowerCase(), confidence = $('confidence').value;
  return report[view].filter(item => {
    if (!['sources','coverage'].includes(view) && confidence !== 'all' && item.confidence !== confidence) return false;
    if (view === 'research' && $('stage-filter').value !== 'all' && item.stage !== $('stage-filter').value) return false;
    if (['endpoints','servers','research'].includes(view)) {
      const relevance=$('relevance-filter').value;
      if(relevance==='focused' && view !== 'research' && !item.research_relevance?.focused) return false;
    }
    const haystack = view === 'sources' ? `${item.path}\n${item.content}` : `${item.value}\n${item.source}\n${item.kind}\n${item.stage || ''}\n${item.target || ''}\n${item.status || ''}\n${item.evidence}\n${JSON.stringify(item.descriptor || item.elf || item.metadata || item.manifest || item.role_hints || '')}\n${(item.methods || []).join('\n')}`;
    return !query || haystack.toLowerCase().includes(query);
  });
}
function render() {
  const list = rows(), pages = Math.max(1, Math.ceil(list.length / pageSize));
  page = Math.min(page, pages - 1);
  $('view-title').replaceChildren(document.createTextNode(titles[view] + ' '), node('span', '', String(list.length)));
  $('confidence').disabled = ['sources','coverage'].includes(view);
  $('stage-filter').hidden = view !== 'research';
  $('relevance-filter').hidden = !['research','endpoints','servers'].includes(view);
  $('findings').replaceChildren();
  if (!report || !list.length) {
    const empty = node('div', 'empty');
    empty.append(node('div','empty-symbol','⌁'),node('h3','', report ? 'لا توجد نتائج مطابقة' : 'التفاصيل تبدأ هنا'),node('p','', report ? 'جرّب قسمًا آخر أو عدّل البحث. غياب النتائج لا يعني غياب الاتصالات.' : 'ارفع ملفًا لاستخراج مؤشرات الاتصال، أو جرّب المثال.'));
    $('findings').append(empty);
  }
  list.slice(page * pageSize, (page + 1) * pageSize).forEach(item => {
    const button = node('button','finding' + (selected === item ? ' selected' : ''));
    const main = node('span','finding-main');
    main.append(node('span','finding-type',view === 'sources' ? item.language.toUpperCase() : item.kind),node('span','finding-value',item.value || item.path));
    if (item.source) main.append(node('span','finding-source',item.source + (item.line ? ':' + item.line : item.offset !== null && item.offset !== undefined ? ' @ 0x' + item.offset.toString(16) : '')));
    button.append(main);
    if (view==='coverage') button.append(node('span','badge ' + (item.status==='scanned' || item.status==='enumerated' ? 'high' : 'low'),item.status));
    if (item.confidence) button.append(node('span','badge ' + item.confidence,confidenceLabels[item.confidence]));
    button.addEventListener('click', () => {selected = item; render(); showDetail(item);});
    $('findings').append(button);
  });
  $('pagination').hidden = list.length <= pageSize;
  $('prev').disabled = page === 0; $('next').disabled = page >= pages - 1;
  $('page-label').textContent = `${page + 1} / ${pages}`;
  if (!selected || !list.includes(selected)) {
    selected = list[page * pageSize] || null;
    if (selected) {
      $('findings').firstElementChild?.classList.add('selected'); showDetail(selected);
    } else {
      $('detail').replaceChildren(node('div','detail-empty','لا يوجد دليل لعرضه.'));
      $('copy').disabled = true; copyText = '';
    }
  }
}
function showDetail(item) {
  const container = node('div','detail-content');
  container.append(node('h3','',item.value || item.path));
  const meta = node('div','detail-meta');
  meta.textContent = view === 'coverage' ? `${item.status} · ${item.size ?? '?'} bytes` : view === 'sources' ? `ملف ${item.language} ${item.truncated ? '· المعاينة مختصرة' : ''}` : `${item.kind} · الثقة: ${confidenceLabels[item.confidence]}`;
  container.append(meta);
  if (item.source) { const source = node('div','detail-meta'); source.append(node('code','',item.source)); container.append(source); }
  if (item.host) container.append(node('div','detail-meta', `Host: ${item.host}${item.port ? ' · Port: ' + item.port : ''}`));
  if (item.class_name) container.append(node('div','detail-meta','Class: ' + item.class_name));
  if (item.method_name) container.append(node('div','detail-meta','Method: ' + item.method_name));
  if (item.method) container.append(node('div','detail-meta','HTTP method: ' + item.method));
  if (item.note) container.append(node('div','detail-meta',item.note));
  function block(label, text) { container.append(node('div','detail-label',label),node('pre','code',text)); }
  if (view==='coverage') block('BYTE COVERAGE ≠ SEMANTIC COMPLETENESS',JSON.stringify(item,null,2));
  if(item.port_literal_candidate || item.region_literal_candidate) block('UNBOUND LITERAL CANDIDATE',JSON.stringify({port:item.port_literal_candidate,region:item.region_literal_candidate,bound_to_endpoint:false},null,2));
  if (item.stage) container.append(node('div','detail-meta',`مرحلة البحث: ${stageLabels[item.stage]} · الهدف: ${item.target}`));
  if (item.research_relevance) block('RESEARCH RELEVANCE · HEURISTIC',JSON.stringify(item.research_relevance,null,2));
  if (item.caller) block('OBSERVED SMALI INVOKE',JSON.stringify({caller:item.caller,callee:item.callee,runtime_transition_proven:false},null,2));
  if (item.elf) {
    const elf=item.elf;
    block(`ELF · ${elf.architecture} · ${elf.bits}-BIT`,JSON.stringify({needed_libraries:elf.needed_libraries,symbol_count:elf.symbol_count,network_symbols:elf.network_symbols,sections:elf.sections,notes:elf.notes},null,2));
  }
  if (item.metadata) block('IL2CPP · STRING TABLES',JSON.stringify(item.metadata,null,2));
  if (item.manifest) block('BUNDLE · DECLARED METADATA',JSON.stringify(item.manifest,null,2));
  if (view === 'servers') block('CORRELATED HOST EVIDENCE · NOT A CALL GRAPH',JSON.stringify({occurrences:item.occurrences,ports:item.ports,schemes:item.schemes,sources:item.sources,role_hints:item.role_hints,colocated_protocol_markers:item.colocated_protocol_markers,locations:item.locations,locations_truncated:item.locations_truncated},null,2));
  if (item.descriptor) block('PARSED DESCRIPTOR · STRUCTURE',JSON.stringify(item.descriptor,null,2));
  if (item.methods) block(`SMALI · ${item.method_count} METHODS / ${item.field_count} FIELDS`,JSON.stringify({methods:item.methods,fields:item.fields,invokes:item.invokes},null,2));
  const source = view === 'sources' ? item : report.sources.find(source => source.path === item.source);
  if (source) {
    const lines = source.content.split('\n');
    const start = view === 'sources' ? 0 : Math.max(0,(item.line || 1) - 9);
    const end = Math.min(lines.length, view === 'sources' ? 400 : start + 28);
    container.append(node('div','detail-label',`SOURCE · ${source.language.toUpperCase()} · ${start + 1}–${end}${source.truncated || end < lines.length ? ' · PREVIEW' : ''}`));
    const pre = node('pre','code');
    lines.slice(start,end).forEach((line,index) => {
      const number = start + index + 1;
      const span = node('span','code-line' + (number === item.line ? ' focus-line' : ''));
      span.append(node('span','line-number',String(number)),document.createTextNode(line || ' '));
      pre.append(span);
    });
    container.append(pre);
    if (item.evidence && item.line > lines.length) block('EVIDENCE · OUTSIDE STORED PREVIEW',item.evidence);
    copyText = view === 'sources' ? source.content : JSON.stringify(item,null,2);
  } else if (item.evidence) {
    block(item.offset !== null && item.offset !== undefined ? `BINARY EVIDENCE · OFFSET 0x${item.offset.toString(16)}` : 'EVIDENCE',item.evidence);
    copyText = JSON.stringify(item,null,2);
  } else copyText = JSON.stringify(item,null,2);
  if (item.schema) block('PROTO SOURCE' + (item.schema_truncated ? ' · TRUNCATED' : ''),item.schema);
  $('detail').replaceChildren(container);
  $('copy').disabled = false;
}
document.querySelectorAll('.nav').forEach(button => button.addEventListener('click',() => {
  view = button.dataset.view; page = 0; selected = null;
  document.querySelectorAll('.nav').forEach(b => {b.classList.toggle('active',b === button); b.setAttribute('aria-current',b === button ? 'page' : 'false');});
  render();
}));
$('profile').addEventListener('change',() => {$('upload-limit').textContent=$('profile').value === 'games' ? 'MAX 2 GiB' : 'MAX 128 MiB';});
$('choose').addEventListener('click',() => $('file-input').click());
$('file-input').addEventListener('change',event => load(event.target.files[0]));
$('demo').addEventListener('click',() => load(null,true));
$('search').addEventListener('input',() => {page=0; render();});
$('confidence').addEventListener('change',() => {page=0; render();});
for(const id of ['stage-filter','relevance-filter']) $(id).addEventListener('change',()=>{page=0;selected=null;render();});
$('prev').addEventListener('click',() => {page--; selected=null; render();});
$('next').addEventListener('click',() => {page++; selected=null; render();});
for (const eventName of ['dragenter','dragover']) $('dropzone').addEventListener(eventName,event => {event.preventDefault(); $('dropzone').classList.add('drag');});
for (const eventName of ['dragleave','drop']) $('dropzone').addEventListener(eventName,event => {event.preventDefault(); $('dropzone').classList.remove('drag');});
$('dropzone').addEventListener('drop',event => load(event.dataTransfer.files[0]));
$('export').addEventListener('click',() => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));
  const link = node('a'); link.href=url; link.download=report.input.name.replace(/[^a-zA-Z0-9._-]/g,'_') + '.protohunter.json';
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url),1000);
});
$('copy').addEventListener('click',async () => {
  try { await navigator.clipboard.writeText(copyText); $('copy').textContent='تم النسخ'; setTimeout(() => {$('copy').textContent='نسخ';},1500); }
  catch { notice('النسخ غير متاح في هذا المتصفح. يمكنك تحديد النص أو تصدير JSON.',true); }
});
fetch('/api/status').then(response => response.json()).then(status => {
  for (const tool of ['jadx','apktool']) $(tool + '-status').textContent=status.tools[tool] ? 'متاح' : 'غير مثبت · اختياري';
  if (status.allow_decoders && (status.tools.jadx || status.tools.apktool)) {
    const option=$('decoder').options[1]; option.disabled=false; option.textContent='تلقائي · المحركات المتاحة';
  }
}).catch(() => notice('تعذّر الاتصال بخادم التحليل.',true));

function renderResearchOverview() {
  $('research-overview').hidden=false;
  const plan=report.research_plan, coverage=report.coverage_summary;
  $('research-stages').replaceChildren();
  for(const stage of ['login','session','transport','messages']) {
    const targets=plan.targets.filter(t=>t.stage===stage), found=targets.filter(t=>t.status==='observed').length;
    const button=node('button','research-stage');
    button.append(node('span','',stageLabels[stage]),node('strong','',`${found} / ${targets.length}`),node('small','','أهداف شوهدت · ليس اكتمال الاسترجاع'));
    button.addEventListener('click',()=>{document.querySelector('[data-view="research"]').click();$('stage-filter').value=stage;page=0;render();});
    $('research-stages').append(button);
  }
  const counts=coverage.file_statuses;
  $('coverage-status').textContent=`التغطية: ${coverage.fully_hashed_files} ملف له بصمة كاملة · ${counts.skipped || 0} متخطّى · ${counts.partial || 0} جزئي · ${counts.error || 0} خطأ. ${coverage.inventory_complete_within_opened_inputs ? 'انتهى حصر المدخلات المفتوحة ضمن الحدود.' : 'الحصر غير مكتمل: راجع الأرشيفات غير المفتوحة وحدود الفحص.'} البصمة لا تثبت فهم كل بايت.`;
  $('target-checklist').replaceChildren(...plan.targets.map(target=>{
    const row=node('div','target-row'); row.append(node('code','',target.target),node('span',target.status==='observed'?'observed':'not-observed',target.status==='observed'?`مرصود (${target.occurrences})`:'لم يُرصد'));
    return row;
  }));
}
