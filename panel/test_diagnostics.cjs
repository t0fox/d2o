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
const dynamic=summary({samples,sample_capacity:1440,event_capacity:32,
 memory_history:{capacity:1440,samples:[[0,0,1024,2048,null,1,13,null]]},
 memory_details:[{name:'d2kc',latest:{smaps_rollup_status:'unavailable'}}]});
assert.match(dynamic,/Снимков: 3 \/ 1440/);
assert.match(dynamic,/завершений поиска: 0 \/ 32/);
assert.match(dynamic,/Снимков памяти: 1 \/ 1440/);
assert.match(dynamic,/smaps_rollup недоступен/);
assert.doesNotMatch(dynamic,/120|64/,'older fixed report limits are not substituted');
assert.match(summary({samples:[],events:[],memory_history:{capacity:1440,samples:[]}}),/первый снимок/);
console.log('сводка диагностики панели прошла');
