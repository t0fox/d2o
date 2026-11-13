'use strict';
const assert=require('node:assert/strict');
const {summary,memoryRows,rowsInRange,seriesEndpoints,formatBytes,coverageText,telegramRows}=require('../internal/web/assets/diagnostics.js');
assert.match(summary({}),/первый снимок/);
const samples=[{at:1,bindings:2,plans:1,processes:[{name:'d2kc',pid:1,rss_kib:1024}]},
 {at:2,bindings:3,plans:1,processes:[{name:'d2kc',pid:2,rss_kib:512}]}];
assert.match(summary({samples}),/\+0.0 за историю этого PID/);
samples.push({at:3,bindings:3,plans:1,processes:[{name:'d2kc',pid:2,rss_kib:1024}]});
assert.match(summary({samples,events:[{outcome:'local-abort'},{outcome:'probe-confirmed'}]}),/результата: 1/);
assert.match(summary({samples}),/\+0.5 за историю этого PID/);
const dynamic=summary({samples,sample_capacity:1440,event_capacity:32,
 memory_history:{capacity:1440,samples:[[0,0,1024,2048,null,4,2,null,512,8,16,4,1,2,3,4,3,1,1]]},
 memory_details:[{name:'d2kc',latest:{smaps_rollup_status:'unsupported',smaps_rollup_errno:2}}],
 memory_tracking:{enabled:true,sites:[{id:'tls13.session',name:'TLS 1.3 session',live_bytes:1536,live_objects:1}]},
 madvise:{successes:10,failures:2,requested_bytes:4096,errno:[{code:22,count:2}]},
 anomalies:[{kind:'unattributed-rss-growth',rss_delta_kib:2048,accounted_delta_kib:0}]});
assert.match(dynamic,/Снимков: 3 \/ 1440/);
assert.match(dynamic,/завершений поиска: 0 \/ 32/);
assert.match(dynamic,/Снимков памяти: 1 \/ 1440/);
assert.match(dynamic,/RssAnon/);
assert.match(dynamic,/каталог/);
assert.match(dynamic,/TLS 1\.3/);
assert.match(dynamic,/madvise/);
assert.match(dynamic,/устойчивый рост RSS/);
assert.match(dynamic,/не подтверждает утечку/);
assert.doesNotMatch(dynamic,/errno 2/);
assert.doesNotMatch(dynamic,/120|64/,'older fixed report limits are not substituted');
assert.match(summary({samples:[],events:[],memory_history:{capacity:1440,samples:[]}}),/первый снимок/);
const fields=['catalog_bytes','http_bytes','tracked_tcp_bytes','tracked_quic_bytes','tracked_tls_bytes','rss_anon_kib',
 'rss_kib','vm_data_kib','at_delta_s','mono_delta_s','d2kc_epoch','smaps_rollup_status_code',
 'smaps_rollup_errno','smaps_rollup_kib','snapshot_bytes','tasks','workers_live','workers_result_pending','workers_join_pending'];
const encode=row=>fields.map(name=>Object.prototype.hasOwnProperty.call(row,name)?row[name]:null);
const controlled={memory_history:{fields,time_base:[1700000000,1000],sample_interval_ms:60000,samples:[
 encode({catalog_bytes:8192,http_bytes:4096,tracked_tcp_bytes:1024,tracked_quic_bytes:4096,tracked_tls_bytes:0,
  rss_anon_kib:512,rss_kib:1024,vm_data_kib:4096,at_delta_s:0,mono_delta_s:0,d2kc_epoch:7,smaps_rollup_status_code:4,
  snapshot_bytes:2048,tasks:2,workers_live:3,workers_result_pending:1,workers_join_pending:1}),
 encode({catalog_bytes:9625,http_bytes:5529,tracked_tcp_bytes:2048,tracked_quic_bytes:2048,tracked_tls_bytes:8192,
  rss_anon_kib:1024,rss_kib:2048,vm_data_kib:6144,at_delta_s:600,mono_delta_s:600,d2kc_epoch:7,smaps_rollup_status_code:4,
  snapshot_bytes:4096,tasks:3,workers_live:4,workers_result_pending:2,workers_join_pending:1})]}};
const controlledRows=memoryRows(controlled),current=controlledRows[1];
assert.equal(current.catalog,9625);
assert.equal(current.http,5529);
assert.equal(formatBytes(current.catalog),'9.4 КиБ');
assert.equal(formatBytes(current.http),'5.4 КиБ');
assert.equal(seriesEndpoints(controlledRows,'rss').delta,1048576);
assert.equal(seriesEndpoints(controlledRows,'rss_anon').delta,512*1024);
assert.equal(seriesEndpoints(controlledRows,'vm_data').delta,2048*1024);
assert.equal(seriesEndpoints(controlledRows,'tracked_tcp').delta,1024);
assert.equal(seriesEndpoints(controlledRows,'tracked_quic').delta,-2048);
assert.equal(seriesEndpoints(controlledRows,'tracked_tls').delta,8192);
assert.match(coverageText(rowsInRange(controlledRows,24,60000),24),/Доступно 10 мин из 24 часа/);
const changedPid=controlledRows.map((row,index)=>({...row,generation:index?8:7}));
assert.equal(seriesEndpoints(changedPid,'rss').delta,null,'RSS change is not calculated across a PID generation change');
assert.equal(seriesEndpoints(controlledRows.map(row=>({...row,generation:null})),'rss').delta,null,'RSS change is unknown without a PID generation');
const absent={memory_history:{fields,time_base:[1700000000,1000],samples:[encode({at_delta_s:0,mono_delta_s:0,rss_kib:1024,
 rss_anon_kib:512,vm_data_kib:2048,smaps_rollup_status_code:4})]}};
assert.equal(memoryRows(absent)[0].anonymous,null,'unavailable smaps is not rendered as zero');
assert.equal(memoryRows(absent)[0].private_dirty,null,'unavailable Private_Dirty is not rendered as zero');
const legacyHistory={memory_history:{time_base:[1700000000,1000],samples:[[0,0,1024,2048,null,4,null,null,512,10,5,4,1,2,3,2,3,1,1]]}};
assert.equal(memoryRows(legacyHistory)[0].catalog,10*1024,'old positional KiB fields remain readable');
const noTime={memory_history:{fields,time_base:[null,null],samples:[encode({rss_kib:1024,at_delta_s:0,mono_delta_s:0})]}};
assert.equal(memoryRows(noTime)[0].time,null,'missing time bases do not become zero');
assert.match(coverageText(rowsInRange(memoryRows(noTime),24,60000),24),/Время снимков отсутствует/);
const tgRows=telegramRows({memory_history:{fields:['at_delta_s','mono_delta_s','rss_kib','rss_anon_kib','vm_data_kib'],
 time_base:[1700000000,500],samples:[[0,0,2048,1024,4096],[60,60,3072,1536,6144]]}});
assert.equal(tgRows[0].rss,2*1024*1024);
assert.equal(tgRows[1].rss_anon,1536*1024);
assert.equal(tgRows[1].time,560);
const trafficFields=['at_delta_s','mono_delta_s','process_id','process_started_at','bytes_from_clients','bytes_from_upstreams'];
const trafficRows=telegramRows({memory_history:{fields:trafficFields,time_base:[1700000000,1000],samples:[
 [0,0,42,1700000000,1000,500],[60,60,42,1700000000,4000,2000],
 [120,120,42,1700000060,10,10],[180,180,42,1700000060,1010,1010]]}});
assert.equal(trafficRows[1].client_rate,50,'rates use the same process generation');
assert.equal(trafficRows[1].upstream_rate,25);
assert.equal(trafficRows[2].client_rate,null,'reused PID with a new start time does not create a negative rate');
assert.equal(trafficRows[3].client_rate,1000/60,'rates resume within the new generation');
const generationFields=['at_delta_s','mono_delta_s','process_id','process_started_at','process_generation',
 'bytes_from_clients','bytes_from_upstreams','active_connections','fd_count','tls_objects','worker_pool_entries',
 'proxy_struct_bytes','connection_struct_bytes','retired_connection_struct_bytes','worker_pool_struct_bytes'];
const generationRows=telegramRows({memory_history:{fields:generationFields,time_base:[1700000000,1000],samples:[
 [0,0,42,1700000000,111,1000,500,2,8,3,1,2048,1024,0,512],
 [60,60,42,1700000000,222,10,10,0,4,0,0,2048,0,0,512]]}});
assert.equal(generationRows[1].client_rate,null,'a new process generation breaks rates even if PID and wall start time were reused');
assert.equal(generationRows[1].process_generation,222);
assert.equal(generationRows[1].worker_pool_bytes,512,'worker pool allocations are retained in compact history');
assert.equal(generationRows[1].active_connections,0);
console.log('сводка диагностики панели прошла');
