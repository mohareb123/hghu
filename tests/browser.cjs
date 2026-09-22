// Optional browser smoke test. Start `python -m protohunter serve` first.
const {chromium} = require('playwright');
const assert = require('node:assert/strict');

(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_EXECUTABLE_PATH || undefined,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  try {
    const page = await browser.newPage({viewport: {width: 1440, height: 1080}, acceptDownloads: true});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => {if (message.type() === 'error') errors.push(message.text());});
    await page.goto(process.env.PROTOHUNTER_URL || 'http://127.0.0.1:8765');
    await page.click('#demo');
    await page.waitForFunction(() => document.querySelector('#stat-endpoints').textContent !== '—');
    assert.equal(await page.locator('#stat-smali').textContent(), '1');
    assert.ok(await page.locator('.finding').count() > 0);
    await page.fill('#search', 'api.example');
    assert.equal(await page.locator('.finding').count(), 2);
    await page.selectOption('#confidence', 'low');
    assert.equal(await page.locator('.finding').count(), 0);
    await page.fill('#search', '');
    await page.selectOption('#confidence', 'all');
    await page.click('[data-view="smali"]');
    assert.ok((await page.locator('#detail').textContent()).includes('METHODS'));
    await page.click('[data-view="sources"]');
    assert.ok((await page.locator('#detail').textContent()).includes('SOURCE'));
    const downloadPromise = page.waitForEvent('download');
    await page.click('#export');
    const download = await downloadPromise;
    assert.ok(download.suggestedFilename().endsWith('.json'));
    const report = JSON.parse(require('node:fs').readFileSync(await download.path(), 'utf8'));
    assert.equal(report.input.demo, true);
    await page.setInputFiles('#file-input', {
      name: 'client.java', mimeType: 'text/plain',
      buffer: Buffer.from('class Client { String u = "https://safe.example.com/api"; String x = "<img src=x onerror=alert(1)>"; }'),
    });
    await page.waitForFunction(() => document.querySelector('#upload-title').textContent === 'client.java');
    await page.click('[data-view="endpoints"]');
    assert.equal(await page.locator('.finding').count(), 1);
    assert.equal(await page.locator('#stat-protobuf').textContent(), '0');
    assert.equal(await page.locator('#detail img').count(), 0);
    const {execFileSync} = require('node:child_process');
    const path = require('node:path');
    const bundle = execFileSync(process.env.PYTHON || 'python', ['-c', `
import sys
sys.path.insert(0, 'tests')
from test_games import zip_bytes, sample_metadata, sample_elf, sample_dex
sys.stdout.buffer.write(zip_bytes({
    'base.apk': zip_bytes({'classes.dex': sample_dex('https://game.example.invalid/login')}),
    'config.arm64.apk': zip_bytes({'lib/arm64-v8a/libil2cpp.so': sample_elf(), 'assets/global-metadata.dat': sample_metadata()})
}))
`], {cwd: path.resolve(__dirname, '..')});
    await page.selectOption('#profile', 'games');
    await page.setInputFiles('#file-input', {name:'synthetic-game.xapk', mimeType:'application/octet-stream', buffer:bundle});
    await page.waitForFunction(() => document.querySelector('#upload-title').textContent === 'synthetic-game.xapk');
    assert.equal(await page.locator('#stat-native').textContent(), '2');
    await page.click('[data-view="native"]');
    assert.ok((await page.locator('#detail').textContent()).includes('AArch64'));
    await page.locator('.finding').filter({hasText:'Unity metadata'}).click();
    assert.ok((await page.locator('#detail').textContent()).includes('literal_count'));
    await page.click('[data-view="bundles"]');
    assert.equal(await page.locator('.finding').count(), 3);
    await page.click('[data-view="servers"]');
    assert.equal(await page.locator('.finding').count(), 1);
    assert.ok((await page.locator('#detail').textContent()).includes('base.apk!classes.dex'));
    const login = execFileSync(process.env.PYTHON || 'python', ['-c', "import sys;sys.path.insert(0,'tests');from test_research import LOGIN;sys.stdout.write(LOGIN)"], {cwd:path.resolve(__dirname,'..')});
    await page.setInputFiles('#file-input', {name:'login-research.smali',mimeType:'text/plain',buffer:login});
    await page.waitForFunction(()=>document.querySelector('#upload-title').textContent==='login-research.smali');
    assert.ok(await page.locator('#research-overview').isVisible());
    await page.click('[data-view="research"]');
    await page.selectOption('#stage-filter','login');
    assert.equal(await page.locator('.finding').filter({hasText:'CSMajorLoginReq'}).count(),1);
    await page.click('[data-view="flow"]');
    assert.ok((await page.locator('#detail').textContent()).includes('GetLoginData'));
    await page.click('[data-view="coverage"]');
    assert.ok((await page.locator('#detail').textContent()).includes('sha256'));
    await page.click('[data-view="endpoints"]');
    await page.selectOption('#relevance-filter','focused');
    assert.equal(await page.locator('.finding').count(),1);
    const researchDownloadPromise=page.waitForEvent('download');
    await page.click('#export');
    const researchDownload=await researchDownloadPromise;
    const researchReport=JSON.parse(require('node:fs').readFileSync(await researchDownload.path(),'utf8'));
    assert.equal(researchReport.coverage_summary.semantic_completeness_guaranteed,false);
    assert.equal(researchReport.flow[0].runtime_transition_proven,false);
    await page.click('[data-view="research"]');
    await page.selectOption('#relevance-filter','all');
    if (process.env.PROTOHUNTER_SCREENSHOTS) {
      require('node:fs').mkdirSync(process.env.PROTOHUNTER_SCREENSHOTS, {recursive:true});
      await page.screenshot({path:path.join(process.env.PROTOHUNTER_SCREENSHOTS, 'games-desktop.png'),fullPage:true});
    }
    await page.setViewportSize({width: 390, height: 844});
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    if (process.env.PROTOHUNTER_SCREENSHOTS) await page.screenshot({path:path.join(process.env.PROTOHUNTER_SCREENSHOTS, 'games-mobile.png'),fullPage:true});
    assert.deepEqual(errors, []);
    console.log('Browser smoke passed: demo, filters, navigation, source, upload, XSS escaping, JSON export, XAPK, ELF/IL2CPP, host correlation, research checklist, call references, coverage, mobile layout.');
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exit(1);});
