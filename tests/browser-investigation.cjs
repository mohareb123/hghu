const {chromium}=require('playwright'),assert=require('node:assert/strict'),{execFileSync}=require('node:child_process'),fs=require('node:fs'),path=require('node:path');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE_PATH||undefined,args:['--no-sandbox','--disable-dev-shm-usage']});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1100},acceptDownloads:true}), errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto(process.env.PROTOHUNTER_URL||'http://127.0.0.1:8765');
  await page.selectOption('#investigate-mode','true');
  const fixture=execFileSync(process.env.PYTHON||'python',['-c',`import sys,io,zipfile
sys.path.insert(0,'tests')
from test_investigation import LOGIN,BUILDER,TRANSPORT
b=io.BytesIO()
with zipfile.ZipFile(b,'w') as z:
 for name,data in [('Login.smali',LOGIN),('Builder.smali',BUILDER),('Transport.smali',TRANSPORT)]: z.writestr(name,data)
sys.stdout.buffer.write(b.getvalue())`],{cwd:path.resolve(__dirname,'..')});
  await page.setInputFiles('#file-input',{name:'investigation.apk',mimeType:'application/octet-stream',buffer:fixture});
  await page.waitForFunction(()=>document.querySelector('#upload-title').textContent==='investigation.apk');
  assert.ok(await page.locator('#investigation-panel').isVisible());
  await page.selectOption('#protocol-category','AUTH');
  await page.locator('#protocol-items button').filter({hasText:'Lsample/CSMajorLoginReq;'}).click();
  let selected=JSON.parse(await page.locator('#protocol-detail').textContent());
  assert.equal(selected.score,58);assert.equal(selected.priority,'RELATED');assert.equal(selected.confidence,'HIGH');
  assert.ok((await page.locator('#protocol-path').textContent()).includes('Socket;->connect'));
  assert.ok(selected.adjacent_edges.length>0);
  await page.click('.bot-mode summary');
  await page.setInputFiles('#bot-files',{name:'old.py',mimeType:'text/plain',buffer:Buffer.from('class CSMajorLoginReq:\n appKey="x"\n appSecret="x"\n accountId=0\n region="x"\n serverId=0\n\nclass GamePacketX:\n pass\n')});
  await page.click('#bot-compare');
  await page.waitForFunction(()=>document.querySelector('#bot-status').textContent.includes('عنصر مقارَن'));
  const bot=JSON.parse(await page.locator('#bot-results').textContent());
  assert.ok(bot.bot_matches.find(x=>x.name==='CSMajorLoginReq').candidates[0].match>.45);
  assert.ok(bot.missing_from_new_version.some(x=>x.name==='GamePacketX'));
  const ready=page.waitForEvent('download');await page.click('#export-protocol');const download=await ready;
  assert.equal(download.suggestedFilename(),'protocol_report.json');
  const report=JSON.parse(fs.readFileSync(await download.path(),'utf8'));assert.equal(report.bot_matches.length,2);
  const zipReady=page.waitForEvent('download');await page.click('#export-sections');const zip=await zipReady;
  const result=JSON.parse(execFileSync(process.env.PYTHON||'python',['-c',"import sys,zipfile,json; z=zipfile.ZipFile(sys.argv[1]); print(z.read('protocol_report.json').decode('utf-8'))",await zip.path()],{encoding:'utf8'}));
  assert.deepEqual(result.bot_matches,report.bot_matches);
  await page.fill('#protocol-search','nothing-matches-this');assert.equal(await page.locator('#protocol-items button').count(),0);
  await page.setViewportSize({width:390,height:844});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
  assert.deepEqual(errors,[]);
  console.log('Investigation browser passed: opt-in APK mode, explained scores, static graph, filters, optional BOT MODE, missing candidates, JSON/ZIP parity, mobile.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
