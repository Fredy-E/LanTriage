'use strict';
// Dependency-free real-Chrome testing; uses Node >= 26 WebSocket.
// Every launch owns a new scratch profile. Never attaches to owner browsers.
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const assert = require('node:assert/strict');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function waitUntil(fn, message = 'condition', timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await fn();
    if (value) return value;
    await delay(40);
  }
  throw new Error('Timed out waiting for ' + message);
}

async function launch(options = {}) {
  if (typeof WebSocket !== 'function') throw new Error('Node 26+ with built-in WebSocket required');
  const scratch = options.scratchDir || process.env.HERMES_TEST_SCRATCH ||
    (process.platform === 'win32' ? path.join(os.homedir(), 'AppData', 'Local', 'hermes', 'cache', 'scratch') : process.env.TMPDIR || os.tmpdir());
  await fs.mkdir(scratch, { recursive: true });
  const profile = await fs.mkdtemp(path.join(scratch, 'phase2-chrome-'));
  const artifactsDir = path.resolve(options.artifactsDir || path.join(profile, 'artifacts'));
  await fs.mkdir(artifactsDir, { recursive: true });
  const executable = options.chromePath || process.env.CHROME_PATH || (process.platform === 'win32'
    ? 'C:/Program Files/Google/Chrome/Application/chrome.exe'
    : '/usr/bin/google-chrome');
  const child = spawn(executable, [
    '--headless=new', '--do-not-de-elevate', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-default-apps', '--disable-sync',
    '--disable-extensions', '--remote-debugging-address=127.0.0.1',
    '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'
  ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let diagnostics = '', spawnError = null, socket = null, sessionId = null;
  let counter = 0, closed = false;
  const pending = new Map(), listeners = new Map();
  const errors = [], requests = [], downloads = [];
  child.on('error', error => { spawnError = error; });
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', data => { diagnostics = (diagnostics + data.toString()).slice(-12000); });
  }
  function emit(method, params, sid) {
    for (const callback of listeners.get(method) || []) callback(params, sid);
  }
  function on(method, callback) {
    const callbacks = listeners.get(method) || [];
    callbacks.push(callback); listeners.set(method, callbacks);
    return () => listeners.set(method, callbacks.filter(item => item !== callback));
  }
  function command(method, params = {}, sid = sessionId) {
    return new Promise((resolve, reject) => {
      if (!socket || socket.readyState !== WebSocket.OPEN) return reject(new Error('CDP socket closed: ' + method));
      const id = ++counter;
      const timer = setTimeout(() => {
        pending.delete(id); reject(new Error('CDP timeout: ' + method));
      }, options.commandTimeoutMs || 15000);
      pending.set(id, { resolve, reject, timer });
      const payload = { id, method, params };
      if (sid) payload.sessionId = sid;
      socket.send(JSON.stringify(payload));
    });
  }
  async function close() {
    if (closed) return;
    closed = true;
    if (socket && socket.readyState === WebSocket.OPEN) {
      await Promise.race([command('Browser.close', {}, null).catch(() => {}), delay(2000)]);
      socket.close();
    }
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(new Error('Owned test browser closed')); }
    pending.clear();
    if (child.exitCode === null && child.signalCode === null && !spawnError) {
      await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(2500)]);
      if (child.exitCode === null && child.signalCode === null) {
        if (process.platform === 'win32') {
          // Re-check the current command line before PID-based cleanup.
          // A recorded launch PID alone must not authorize killing a reused PID.
          const expected = ('--user-data-dir=' + profile).replace(/'/g, "''");
          const script = '$p=Get-CimInstance Win32_Process -Filter "ProcessId=' + child.pid + '"; ' +
            'if($p -and $p.CommandLine -and $p.CommandLine.Contains(\'' + expected + '\')) {exit 0} else {exit 2}';
          const proof = spawn(path.join(process.env.SystemRoot || 'C:/Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
            ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, stdio: 'ignore' });
          const owned = await Promise.race([new Promise(resolve => {
            proof.once('exit', code => resolve(code === 0)); proof.once('error', () => resolve(false));
          }), delay(4000).then(() => false)]);
          if (owned) {
            const killer = spawn(path.join(process.env.SystemRoot || 'C:/Windows', 'System32', 'taskkill.exe'),
              ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
            await Promise.race([new Promise(resolve => { killer.once('exit', resolve); killer.once('error', resolve); }), delay(3000)]);
          } else console.warn('Skipped PID cleanup: current profile ownership was not proven.');
        } else child.kill('SIGKILL');
      }
    }
    // Only the newly generated profile is removable; report artifacts are retained.
    try {
      if (!artifactsDir.startsWith(profile + path.sep)) {
        await fs.rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      }
    } catch (error) { console.warn('Owned profile cleanup: ' + error.message); }
  }
  try {
    const portInfo = await waitUntil(async () => {
      if (spawnError) throw spawnError;
      // On elevated Windows Chrome can relaunch and let its launcher exit 0.
      if (child.exitCode !== null && child.exitCode !== 0) throw new Error('Chrome exited: ' + child.exitCode + '\n' + diagnostics);
      try { return await fs.readFile(path.join(profile, 'DevToolsActivePort'), 'utf8'); }
      catch (error) {
        // Chrome can briefly hold its own port file while writing it on Windows.
        // Retry only these transient startup states within the existing deadline.
        if (error.code === 'ENOENT' || error.code === 'EBUSY') return null;
        throw error;
      }
    }, 'owned Chrome debugger', 20000);
    const [port, endpoint] = portInfo.trim().split(/\r?\n/);
    socket = new WebSocket('ws://127.0.0.1:' + port + endpoint);
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      if (message.id) {
        const item = pending.get(message.id);
        if (!item) return;
        pending.delete(message.id); clearTimeout(item.timer);
        if (message.error) item.reject(new Error(JSON.stringify(message.error)));
        else item.resolve(message.result || {});
      } else emit(message.method, message.params || {}, message.sessionId);
    });
    socket.addEventListener('close', () => {
      for (const item of pending.values()) { clearTimeout(item.timer); item.reject(new Error('CDP disconnected')); }
      pending.clear();
    });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('CDP connection timeout')), 10000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      socket.addEventListener('error', () => { clearTimeout(timer); reject(new Error('CDP connection failed')); }, { once: true });
    });
    const { targetId } = await command('Target.createTarget', { url: 'about:blank' }, null);
    sessionId = (await command('Target.attachToTarget', { targetId, flatten: true }, null)).sessionId;
    for (const domain of ['Page', 'Runtime', 'DOM', 'Network']) await command(domain + '.enable');
    await command('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: artifactsDir, eventsEnabled: true }, null);
    on('Runtime.exceptionThrown', (params, sid) => {
      if (sid === sessionId) errors.push(params.exceptionDetails.exception?.description || params.exceptionDetails.text);
    });
    on('Runtime.consoleAPICalled', (params, sid) => {
      if (sid === sessionId && params.type === 'error') errors.push(params.args.map(arg => arg.value ?? arg.description).join(' '));
    });
    on('Network.requestWillBeSent', (params, sid) => {
      if (sid === sessionId && /^https?:/i.test(params.request.url)) requests.push(params.request.url);
    });
    on('Browser.downloadWillBegin', params => downloads.push({ ...params, state: 'inProgress' }));
    on('Browser.downloadProgress', params => {
      const item = downloads.find(item => item.guid === params.guid);
      if (item) Object.assign(item, params);
    });
    async function evaluate(expression) {
      const response = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
      if (response.exceptionDetails) throw new Error(response.exceptionDetails.exception?.description || response.exceptionDetails.text);
      return response.result.value;
    }
    const page = {
      profile, artifactsDir, errors, requests, downloads, on, command, evaluate, close,
      async goto(fileOrUrl) {
        const url = /^(file|https?|about):/.test(fileOrUrl) ? fileOrUrl : pathToFileURL(path.resolve(fileOrUrl)).href;
        const result = await command('Page.navigate', { url });
        if (result.errorText) throw new Error(result.errorText);
        await waitUntil(() => evaluate('location.href === ' + JSON.stringify(url) + ' && document.readyState === "complete"'), 'page load');
      },
      async waitFor(expression, message, timeoutMs) {
        return waitUntil(() => evaluate(expression), message || expression, timeoutMs);
      },
      async click(selector) {
        await evaluate('(() => {const n=document.querySelector(' + JSON.stringify(selector) + '); if(!n) throw new Error("Missing selector"); if(n.disabled) throw new Error("Disabled control"); n.click(); return true;})()');
      },
      async fill(selector, value) {
        await evaluate('(() => {const n=document.querySelector(' + JSON.stringify(selector) + '); if(!n) throw new Error("Missing selector"); n.value=' + JSON.stringify(value) + '; n.dispatchEvent(new Event("input",{bubbles:true})); n.dispatchEvent(new Event("change",{bubbles:true})); return true;})()');
      },
      async check(selector, checked) {
        await evaluate('(() => {const n=document.querySelector(' + JSON.stringify(selector) + '); if(!n) throw new Error("Missing selector"); if(n.checked!==' + JSON.stringify(Boolean(checked)) + ') n.click(); return true;})()');
      },
      async setInputFiles(selector, files) {
        const { root } = await command('DOM.getDocument');
        const { nodeId } = await command('DOM.querySelector', { nodeId: root.nodeId, selector });
        if (!nodeId) throw new Error('Missing file input: ' + selector);
        await command('DOM.setFileInputFiles', { nodeId, files: (Array.isArray(files) ? files : [files]).map(file => path.resolve(file)) });
      },
      async key(key) {
        const codes = { Tab: 9, Enter: 13, Escape: 27, ArrowDown: 40, ArrowUp: 38 };
        if (!codes[key]) throw new Error('Unsupported key: ' + key);
        await command('Input.dispatchKeyEvent', { type: 'keyDown', key, code: key, windowsVirtualKeyCode: codes[key], nativeVirtualKeyCode: codes[key] });
        await command('Input.dispatchKeyEvent', { type: 'keyUp', key, code: key, windowsVirtualKeyCode: codes[key], nativeVirtualKeyCode: codes[key] });
      },
      async viewport(width, height) {
        await command('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
      },
      async screenshot(filename) {
        const metrics = await command('Page.getLayoutMetrics');
        const size = metrics.cssContentSize || metrics.contentSize;
        const shot = await command('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true,
          clip: { x: 0, y: 0, width: Math.ceil(size.width), height: Math.min(12000, Math.ceil(size.height)), scale: 1 } });
        const output = path.resolve(filename);
        await fs.mkdir(path.dirname(output), { recursive: true });
        await fs.writeFile(output, Buffer.from(shot.data, 'base64'));
        return output;
      },
      async download(selector) {
        const before = downloads.length;
        await page.click(selector);
        const item = await waitUntil(() => downloads[before], 'download start');
        await waitUntil(() => item.state === 'completed' || item.state === 'canceled', 'download completion');
        assert.equal(item.state, 'completed', 'Download canceled');
        assert.equal(path.basename(item.suggestedFilename), item.suggestedFilename, 'Invalid suggested file name');
        const filename = item.filePath || path.join(artifactsDir, item.suggestedFilename);
        const bytes = await fs.readFile(filename);
        return { filename, bytes, text: bytes.toString('utf8'), suggestedFilename: item.suggestedFilename };
      },
      assertClean() {
        assert.deepEqual(errors, [], 'Page or console errors');
        assert.deepEqual(requests, [], 'Unexpected HTTP(S) requests from app');
      }
    };
    await page.viewport(1440, 1000);
    return page;
  } catch (error) { await close(); throw error; }
}
module.exports = { launch, waitUntil };
