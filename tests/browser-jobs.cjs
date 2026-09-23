// UI state-machine smoke. Desktop chooser and long job are simulated; APIs are tested separately.
const {chromium}=require('playwright');
const assert=require('node:assert/strict');
(async()=>{
  const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE_PATH || undefined,args:['--no-sandbox','--disable-dev-shm-usage']});
  try{
    const page=await browser.newPage({viewport:{width:1440,height:1000}});
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    let cancelled=false;
    const tools={java:true,apktool:true,jadx:false,apktool_jar:'C:\\Tools\\apktool.jar',java_path:'C:\\Java\\bin\\java.exe'};
    await page.route('**/api/status',route=>route.fulfill({json:{version:'0.6.0',tools,allow_decoders:true,desktop_tools:true,native_picker:true,config_token:'test-token'}}));
    for(const path of ['choose-tool','tools','local-file'])await page.route('**/api/'+path+'*',route=>{
      assert.equal(route.request().headers()['x-protohunter-config-token'],'test-token');
      const body=route.request().postDataJSON();
      route.fulfill({status:path==='local-file'?202:200,json:path==='tools'?{tools,checks:[{tool:'Java',ok:true,output:'test-17'},{tool:'Apktool',ok:true,output:'fixture-1.0'}]}:path==='choose-tool'?{path:body.kind==='java'?tools.java_path:tools.apktool_jar}:{job_id:'fixture',name:'local.apk',local:true}});
    });
    await page.route('**/api/jobs/fixture**',route=>{
      if(route.request().url().endsWith('/cancel'))cancelled=true;
      route.fulfill({json:{id:'fixture',status:cancelled?'cancelled':'running',progress:{stage:'scanning',file:'base.apk!classes.dex',files_scanned:42},elapsed_seconds:3}});
    });
    await page.goto(process.env.PROTOHUNTER_URL || 'http://127.0.0.1:8765');
    await page.locator('#open-local').waitFor({state:'visible'});
    await page.click('#tool-settings summary');
    await page.click('#pick-jar');
    await page.waitForFunction(()=>!document.querySelector('#save-tools').disabled);
    assert.equal(await page.inputValue('#apktool-path'),tools.apktool_jar);
    await page.click('#save-tools');
    await page.waitForFunction(()=>document.querySelector('#tool-result').textContent.includes('fixture-1.0'));
    await page.selectOption('#decoder','apktool');
    await page.click('#open-local');
    await page.waitForFunction(()=>document.querySelector('#progress-detail').textContent.includes('classes.dex'));
    assert.equal(await page.locator('#progress-bar').getAttribute('value'),null);
    assert.ok(await page.locator('#choose').isDisabled());
    await page.click('#cancel-job');
    await page.waitForFunction(()=>!document.querySelector('#choose').disabled);
    assert.ok((await page.locator('#notification').textContent()).includes('تم إلغاء التحليل'));
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    assert.deepEqual(errors,[]);
    console.log('Browser jobs smoke passed: simulated desktop settings, JAR selection/probe, direct open, stage progress, cancellation, mobile settings layout.');
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1);});
