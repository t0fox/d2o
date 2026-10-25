"use strict";
// Опрос: один запрос за раз, конечный срок, скрытая вкладка не опрашивает.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

async function main() {
  let visibility, calls = 0, aborted = 0, updateCalls = 0;
  const intervals = [], timers = new Map(); let next = 0;
  const stub = () => ({
    get ownerDocument() { return document; },
    addEventListener() {}, setAttribute() {}, removeAttribute() {}, replaceChildren() {}, appendChild() {},
    querySelector: () => stub(), querySelectorAll: () => [], contains: () => false, children: [], style: { setProperty() {} },
  });
  const document = {
    hidden: false, readyState: 'complete', body: stub(),
    getElementById: () => stub(), createElement: () => stub(), createTextNode: () => stub(),
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener(name, fn) { if (name === 'visibilitychange') visibility = fn; },
  };
  const window = {
    document, AbortController, crypto:require("node:crypto").webcrypto,
    setTimeout(fn, ms) { timers.set(++next, { fn, ms }); return next; },
    clearTimeout(id) { timers.delete(id); },
    setInterval(fn, ms) { intervals.push({ fn, ms }); },
    fetch(url, options) {
      if (url.startsWith("/api/update")) { updateCalls++; return Promise.resolve({ ok:true, status:200, json:async()=>({state:"unchecked"}) }); }
      calls++;
      return new Promise((resolve, reject) => {
        options.signal.addEventListener('abort', () => { aborted++; reject(new Error('aborted')); });
      });
    },
  };
  vm.runInNewContext(fs.readFileSync('../internal/web/assets/panel.js', 'utf8'), { window, AbortController, Date, JSON, Math, Object, String, Number, Array, Error, Promise });
  assert.equal(calls, 1, 'панель сразу получает состояние');
  assert.equal(updateCalls, 1, 'панель сразу проверяет обновления');
  const poll = intervals.find(i => i.ms === 2000);
  assert.ok(poll, 'опрос состояния работает по таймеру');
  for (let i = 0; i < 12; i++) poll.fn();
  assert.equal(calls, 1, 'ожидающий запрос состояния блокирует повторный запрос');
  const deadline = [...timers.values()].find(t => t.ms === 5000);
  assert.ok(deadline, 'для запроса состояния установлен конечный срок');
  deadline.fn();
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(aborted, 1, 'по истечении срока запрос отменяется');
  const updatePoll = intervals.filter(i => i.ms === 2000)[1];
  assert.ok(updatePoll, 'у опроса обновлений отдельный таймер');
  updatePoll.fn();
  assert.equal(updateCalls, 1, 'таймер пропускает опрос обновлений в простое');
  document.hidden = true;
  poll.fn();
  assert.equal(calls, 1, 'скрытая вкладка не опрашивает состояние');
  document.hidden = false;
  visibility();
  assert.equal(calls, 2, 'после возврата на панель опрос сразу возобновляется');
  assert.equal(updateCalls, 2, 'после возврата панель сразу проверяет обновления');
  console.log('опрос панели: параллельные запросы, срок ожидания и видимость проверены');
}
main().catch(e => { console.error(e); process.exitCode = 1; });
