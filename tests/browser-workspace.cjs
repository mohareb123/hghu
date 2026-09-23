// Real project API + real subprocesses running synthetic engine fixtures, not real decompilers.
const {chromium}=require('playwright'), {spawn}=require('node:child_process'), path=require('node:path'), assert=require('node:assert/strict');
(async()=>{
  const server=spawn(process.env.PYTHON || 'python',[path.join(__dirname,'workspace_fixture_server.py')],{stdio:['ignore','pipe','pipe']});
  let browser;
  try{
    const url=await new Promise((resolve,reject)=>{
      const timeout=setTimeout(()=>reject(new Error('Fixture server startup timeout')),15000);
      server.stdout.on('data',chunk=>{const m=String(chunk).match(/READY (http:\/\/127\.0\.0\.1:\d+)/);if(m){clearTimeout(timeout);resolve(m[1]);}});
      server.once('exit',code=>{clearTimeout(timeout);reject(new Error('Fixture server exited '+code));});
      server.stderr.on('data',chunk=>{if(String(chunk).includes('Traceback'))console.error(String(chunk));});
    });
    browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE_PATH || undefined,args:['--no-sandbox','--disable-dev-shm-usage']});
    const page=await browser.newPage({viewport:{width:1440,height:1100}}), errors=[];
    page.on('pageerror',error=>errors.push(error.message));
    page.on('dialog',dialog=>dialog.accept());
    await page.goto(url);
    await page.waitForFunction(()=>document.querySelector('#ws-project').options.length>1);
    await page.selectOption('#ws-project',{index:1});
    await page.waitForFunction(()=>document.querySelector('#ws-unit').options.length===1 && !document.querySelector('#demo').disabled);
    async function run(operation){
      await page.click(`[data-operation="${operation}"]`);
      try{await page.waitForFunction(()=>document.querySelector('#ws-message').textContent.startsWith('اكتملت العملية') && !document.querySelector('#demo').disabled);}
      catch(error){throw new Error(operation+': '+await page.locator('#ws-message').textContent()+' / '+await page.locator('#ws-log').textContent(),{cause:error});}
    }
    await run('apktool');
    await page.locator('.ws-file').filter({hasText:'Example.smali'}).click();
    await page.waitForFunction(()=>!document.querySelector('#ws-save').disabled);
    const original=await page.inputValue('#ws-code');
    await page.fill('#ws-code',original.replace('CSMajorLoginReq','CSMajorLoginResp'));
    await page.click('#ws-diff');
    await page.waitForFunction(()=>document.querySelector('#ws-diff-text').textContent.includes('CSMajorLoginResp'));
    await page.click('#ws-save');
    await page.waitForFunction(()=>document.querySelector('#ws-message').textContent.startsWith('تم الحفظ') && !document.querySelector('#ws-save').disabled);
    await run('jadx');
    await page.click('.ws-unity summary');await page.click('#ws-discover');
    await page.waitForFunction(()=>document.querySelector('#ws-binary').options.length===1 && !document.querySelector('#demo').disabled);
    await run('il2cpp');
    await page.locator('.ws-file').filter({hasText:'dump.cs'}).click();
    await page.waitForFunction(()=>document.querySelector('#ws-code').value.includes('class Player'));
    assert.ok(await page.locator('#ws-code').evaluate(el=>el.readOnly));
    await run('inspect');
    assert.ok((await page.locator('#report-meta').textContent()).includes('ملف'));
    const sections=await require('./browser-export-helper.cjs')(page);
    assert.ok(sections.server.length>0);
    assert.ok((await page.locator('#ws-message').textContent()).includes('sections'));
    await run('build');
    assert.equal(await page.locator('.ws-file').filter({hasText:'unsigned.apk'}).count(),1);
    await page.locator('.ws-file').filter({hasText:'Example.smali'}).click();
    await page.waitForFunction(()=>!document.querySelector('#ws-restore').disabled);
    await page.click('#ws-restore');
    await page.waitForFunction(()=>document.querySelector('#ws-message').textContent.startsWith('تمت الاستعادة'));
    assert.equal(await page.inputValue('#ws-code'),original);
    await page.setViewportSize({width:390,height:844});
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
    assert.deepEqual(errors,[]);
    console.log('Workspace browser passed: persisted project, 3 synthetic adapters, diff/save/restore, readonly Java/Unity, combined inspection, build, mobile layout.');
  }finally{if(browser)await browser.close();server.kill();}
})().catch(error=>{console.error(error);process.exitCode=1;});
