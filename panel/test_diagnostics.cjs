'use strict';
const assert=require('node:assert/strict');
const {summary}=require('../internal/web/assets/diagnostics.js');
assert.match(summary({}),/первый снимок/);
const samples=[{at:1,bindings:2,plans:1,processes:[{name:'d2kc',pid:1,rss_kib:1024}]},
 {at:2,bindings:3,plans:1,processes:[{name:'d2kc',pid:2,rss_kib:512}]}];
assert.match(summary({samples}),/\+0.0 за историю этого PID/);
samples.push({at:3,bindings:3,plans:1,processes:[{name:'d2kc',pid:2,rss_kib:1024}]});
assert.match(summary({samples,events:[{outcome:'local-abort'},{outcome:'probe-confirmed'}]}),/результата: 1/);
assert.match(summary({samples}),/\+0.5 за историю этого PID/);
console.log('сводка диагностики панели прошла');
