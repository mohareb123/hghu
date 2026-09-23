const {execFileSync}=require('node:child_process'), assert=require('node:assert/strict');
module.exports=async function exportSections(page){
  const ready=page.waitForEvent('download');
  await page.click('#export-sections');
  const download=await ready;
  assert.ok(download.suggestedFilename().endsWith('.sections.zip'));
  const value=JSON.parse(execFileSync(process.env.PYTHON || 'python',['-c',`
import sys,zipfile,json
with zipfile.ZipFile(sys.argv[1]) as z:
    assert z.testzip() is None
    assert all(name in z.namelist() for name in ('server.txt','server.json','protocol.txt','protocol.json','README.txt'))
    print(json.dumps({name:json.loads(z.read(name+'.json')) for name in ('server','protocol','index','metadata')}))
`,await download.path()],{encoding:'utf8'}));
  await page.waitForFunction(()=>!document.querySelector('#export-sections').disabled);
  return value;
};
