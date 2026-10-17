const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const { spawn, spawnSync } = require('node:child_process');
const path = require('node:path');

async function main() {
  const exe = path.resolve('d2kpanel');
  const version = spawnSync(exe, ['--version'], { encoding: 'utf8' });
  assert.equal(version.status, 0, version.stderr);
  assert.match(version.stdout, /^d2kpanel\b/);
  assert.match(version.stdout, /features=.*telegram-control/,
    'the installed ARM64 bundle must advertise Telegram control CLI support');

  const bad = spawnSync(exe, ['--unknown-option'], { encoding: 'utf8' });
  assert.notEqual(bad.status, 0, 'unknown options must not silently start a default service');

  const invalidConfig = path.join(os.tmpdir(), `d2k-panel-invalid-${process.pid}`);
  fs.writeFileSync(invalidConfig, 'MODE=not-a-mode\n');
  const invalid = spawnSync(exe, ['serve', '--config', invalidConfig, '--listen', ''], { encoding: 'utf8' });
  fs.rmSync(invalidConfig, { force: true });
  assert.notEqual(invalid.status, 0, 'invalid MODE must be rejected like the canonical config loader');
  fs.writeFileSync(invalidConfig, 'MODE=not-a-mode\n');
  const invalidWithOverrides = spawnSync(exe, [
    'serve', '--config', invalidConfig, '--listen', '', '--mode', 'observe',
    '--state-dir', '/tmp/d2k-panel-invalid-state', '--queue', '2000',
  ], { encoding: 'utf8' });
  fs.rmSync(invalidConfig, { force: true });
  assert.notEqual(invalidWithOverrides.status, 0,
    'explicit runtime options must not let an invalid on-disk config pass silently');
  const invalidOverride = spawnSync(exe, ['serve', '--mode', 'not-a-mode', '--listen', ''], { encoding: 'utf8' });
  assert.notEqual(invalidOverride.status, 0, 'invalid CLI MODE must not bypass configuration validation');

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'd2k-panel-cli-'));
  const port = await new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '0.0.0.0', () => {
      const address = probe.address();
      probe.close((error) => error ? reject(error) : resolve(address.port));
    });
  });
  const stateDir = path.join(temp, 'state');
  const configPath = path.join(temp, 'config');
  const servicePath = path.join(temp, 'slow-service');
  fs.writeFileSync(servicePath, '#!/bin/sh\nsleep 1\nexit 7\n', { mode: 0o700 });
  // The shipped config comes first: every key the installer writes must be
  // known to the panel (field 04.10: D2K_PPE_DEOFFLOAD showed up as
  // «Непонятные ключи — эта сборка их не читает» for every user).
  const shipped = fs.readFileSync(path.join(__dirname, '../files/config'), 'utf8');
  fs.writeFileSync(configPath, shipped +
    `MODE=apply\nPANEL_LISTEN=0.0.0.0:${port}\nSTATE_DIR=${stateDir}\nQUEUE_NUM=4321\nFUTURE_OPTION=preserve-me\n`);
  const child = spawn(exe, [
    'serve', '--config', configPath,
    '--live', '/tmp/d2k-panel-no-live-file',
    '--assets', '../internal/web/assets',
    '--service', servicePath,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = '';
  child.stdout.on('data', (x) => { logs += x; });
  child.stderr.on('data', (x) => { logs += x; });

  try {
    let response;
    for (let i = 0; i < 50; i++) {
      if (child.exitCode !== null) throw new Error(`server exited early (${child.exitCode}): ${logs}`);
      try {
        response = await fetch(`http://127.0.0.1:${port}/api/status`, { signal: AbortSignal.timeout(300) });
        break;
      } catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
    }
    assert.ok(response, `panel did not start: ${logs}`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-security-policy'), /default-src 'none'/);
    const payload = await response.json();
    assert.equal(payload.knowledge.linked, false,
      'missing live knowledge is unavailable, not an empty healthy catalog');
    assert.equal(payload.snapshot.mode, 'apply');
    assert.equal(payload.snapshot.controls_enabled, true,
      'controls should remain active for a panel intentionally bound to a router interface');
    assert.equal(payload.snapshot.queue_num, 4321);
    assert.equal(payload.snapshot.config_exists, true);
    assert.equal(payload.snapshot.state_dir, stateDir);
    assert.deepEqual(payload.snapshot.unknown_keys, ['FUTURE_OPTION']);

    await new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
        socket.write('GET /assets/panel.js HTTP/1.1\r\nHost: localhost\r\n\r\n');
        socket.destroy();
        resolve();
      });
      socket.once('error', reject);
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(child.exitCode, null, 'a client disconnect must not terminate the panel process');
    const afterDisconnect = await fetch(`http://127.0.0.1:${port}/api/status`);
    assert.equal(afterDisconnect.status, 200, 'panel must continue serving after client disconnect');

    const page = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-security-policy'), /font-src 'self'/,
      'The router must allow the offline display font without allowing remote fonts');
    const pageText = await page.text();
    assert.match(pageText, /id="app"/);
    assert.match(pageText, /rel="icon"[^>]+href="\/assets\/favicon\.svg"/,
      'The installed panel must declare its local favicon');
    for (const [asset, mime] of [
      ['favicon.svg', 'image/svg+xml'], ['onest.woff2', 'font/woff2'],
      ['gsap.js', 'application/javascript; charset=utf-8'],
      ['telegram-flow-prototype.js', 'application/javascript; charset=utf-8'], ['jbmono.woff2', 'font/woff2']
    ]) {
      const r = await fetch(`http://127.0.0.1:${port}/assets/${asset}`);
      assert.equal(r.status, 200, asset + ' must be served by the real C panel');
      assert.equal(r.headers.get('content-type'), mime);
      assert.ok((await r.arrayBuffer()).byteLength > 100);
    }

    const control = await fetch(`http://127.0.0.1:${port}/api/control/stop`, {
      method: 'POST', headers: { Origin: `http://127.0.0.1:${port}` },
      signal: AbortSignal.timeout(500),
    });
    assert.equal(control.status, 202, 'a slow service command must return promptly');
    await control.text();
    const during = await fetch(`http://127.0.0.1:${port}/api/status`, { signal: AbortSignal.timeout(500) });
    assert.equal((await during.json()).snapshot.control_state, 'running');
    let state;
    for (let i = 0; i < 60; i++) {
      await new Promise(resolve => setTimeout(resolve, 50));
      const r = await fetch(`http://127.0.0.1:${port}/api/status`, { signal: AbortSignal.timeout(500) });
      state = (await r.json()).snapshot.control_state;
      if (state !== 'running') break;
    }
    assert.equal(state, 'failed', 'accepted must not be presented as a successful service operation');
  } finally {
    child.kill('SIGTERM');
    await Promise.race([
      new Promise((resolve) => child.once('exit', resolve)),
      new Promise((_, reject) => setTimeout(() => reject(new Error(`server ignored SIGTERM: ${logs}`)), 3000)),
    ]);
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

main().then(() => console.log('C panel executable: all checks passed'))
  .catch((err) => { console.error(err); process.exitCode = 1; });
