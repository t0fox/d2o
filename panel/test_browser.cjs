"use strict";
// Браузер → настоящий C-сервер панели (HTTP, CSP, API) → изолированная запись команд службы.
// Ни роутера, ни /opt: всё во временном каталоге.
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {spawn}=require('node:child_process');
const profile=fs.mkdtempSync(path.join(os.tmpdir(),'d2k-browser-'));
const chromeArgs=['--headless','--no-first-run','--hide-scrollbars','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'];
// The isolated GitHub runner restricts Chrome's user namespace sandbox.
if(process.env.D2K_CHROME_NO_SANDBOX==='1')chromeArgs.unshift('--no-sandbox');
let chromeError='';
const chrome=spawn(process.env.CHROME_BIN || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
 chromeArgs,{stdio:['ignore','ignore','pipe']});
chrome.on('error',e=>{chromeError+=e.message;});
chrome.stderr.on('data',data=>{chromeError=(chromeError+data.toString()).slice(-4000);});
const now=Date.now(),iso=s=>new Date(now-s*1000).toISOString();
const fixture={telegramStats:{
 active_connections:4,process_started_at:Math.floor(now/1000)-3600,accepted_connections:77,max_connections:256,
 connections_started:77,bytes_from_clients:1200,bytes_from_upstreams:980,wss_attempts:12,
 wss_failures:2,wss_responses:5,cf_wss_responses:1,last_success_dc:2,last_success_route:3,
 last_success_latency_ms:42,last_success_age_ms:100,last_failure_dc:4,last_failure_route:3,
 last_failure_stage:4,last_failure_age_ms:9000,route_sessions_truncated:false,
 route_cooldown_ms:30000,route_cooldowns:[{dc:4,is_media:true,transport:'cloudflare_proxy',remaining_ms:28750,failure_stage:3}],
 client_response_latency_samples:5,client_response_latency_p50_us:42700,client_response_latency_p95_us:187000,
 active_sessions:[
  {id:71,dc:2,is_media:false,stage:'upstream_ready',direct_state:'selected',direct_transport:'cloudflare_proxy',
   fallback_state:'idle',fallback_transport:null,selected_transport:'cloudflare_proxy',telegram_response_seen:false,
   bytes_from_clients:640,bytes_from_upstreams:0,events:[]},
  {id:72,dc:4,is_media:true,stage:'routing',direct_state:'failed',direct_transport:'cloudflare_proxy',
   fallback_state:'connecting',fallback_transport:'cloudflare_worker',selected_transport:null,telegram_response_seen:false,
   bytes_from_clients:0,bytes_from_upstreams:0,
   events:[{sequence:1,age_ms:390,branch:'direct',transport:'cloudflare_proxy',state:'connecting'},
    {sequence:2,age_ms:120,failure_stage:3,branch:'direct',transport:'cloudflare_proxy',state:'failed'},
    {sequence:3,age_ms:80,branch:'fallback',transport:'cloudflare_worker',state:'connecting'}]},
  {id:73,dc:203,is_media:true,stage:'first_wss_binary_response',direct_state:'selected',
   direct_transport:'cloudflare_proxy',fallback_state:'idle',fallback_transport:null,
   selected_transport:'cloudflare_proxy',telegram_response_seen:true,
   bytes_from_clients:900,bytes_from_upstreams:760,
   events:[{sequence:1,age_ms:220,branch:'direct',transport:'cloudflare_proxy',state:'selected'},
    {sequence:2,age_ms:40,branch:'direct',transport:'cloudflare_proxy',state:'first_binary_response'}]},
  {id:74,dc:null,is_media:null,stage:'upstream_ready',direct_state:'idle',
   direct_transport:null,fallback_state:'selected',fallback_transport:'cloudflare_worker',
   selected_transport:'cloudflare_worker',telegram_response_seen:false,
   bytes_from_clients:0,bytes_from_upstreams:0,events:[]}
 ]},knowledge:{
 searches:[
  {target:'rutracker.org',family:4,transport:6,ip:'104.21.32.39',port:443,phase:'распознаём поведение',since:iso(40),attempts:0,probes:5,candidate:'',source:'',question:'принимает ли ответ на усечённое приветствие'},
  {target:'video.example',family:6,transport:17,ip:'2001:db8::5',port:443,phase:'проверяем готовое узнанной коробки',since:iso(200),attempts:1,probes:3,candidate:'план поставлен',source:'готовый план узнанной коробки'},
  {target:'queued.example',family:4,transport:6,ip:'192.0.2.7',port:443,phase:'ожидает безопасного слота замера',since:iso(20),attempts:0,probes:0,candidate:'',source:''}
 ],
  groups:[
   {suffix:'example.com',transport:6,family:4,shape:1,evidence_count:3,plan_id:'plan-a',probe_path:'/',ech_origin:'',active:true,
    evidence:['a.example.com','b.example.com','c.example.com'],exceptions:[{name:'skip.example.com'}]},
   {suffix:'googlevideo.com',transport:6,family:4,shape:1,evidence_count:5,plan_id:'plan-a',probe_path:'/',ech_origin:'',active:false,
    install_state:'pending',install_reason:'',
    evidence:['rr-a.googlevideo.com','rr-b.googlevideo.com','rr-c.googlevideo.com','rr-d.googlevideo.com','rr-e.googlevideo.com'],
    exceptions:[{name:'clean.googlevideo.com'}]}
  ],
 boxes:[{id:'box-a',created:iso(3600),updated:iso(60),signals:[{kind:'silent',human:'ответа на приветствие не было',seen:3}],
  plans:[{id:'plan-a',proto:'tls',successes:4,enabled:true,human:'',text:'d2k-plan 1 1\nproto tcp tls\nsplit payload_start +1\norder reverse\n'}],
  bindings:[
   {target:'<img src=x onerror=alert(1)>',family:4,transport:6,shape:1,kind:'name',level:2,level_name:'сервер ответил',successes:1,confirmed:iso(90),enabled:true,recheck:false},
   {target:'a.example.com',family:4,transport:6,shape:1,kind:'name',level:3,level_name:'обмен прошёл',successes:2,confirmed:iso(120),enabled:true,recheck:false},
   {target:'a.example.com',family:6,transport:6,shape:1,kind:'name',level:3,level_name:'обмен прошёл',successes:1,confirmed:iso(130),enabled:true,recheck:true},
   {target:'skip.example.com',family:4,transport:6,shape:1,kind:'name',level:3,level_name:'обмен прошёл',successes:1,confirmed:iso(140),enabled:true,recheck:false}
  ]}],
  measurements:{active:1,limit:4,queued:0,cores:2,free_pct:80},targets:4,confirms:7,probes_used:30,client_unfit:0}};
function diagnosticFixture(kind='full'){
 const now=Math.floor(Date.now()/1000);
  const tgFields=['at_delta_s','mono_delta_s','rss_kib','rss_hwm_kib','rss_anon_kib','vm_data_kib','vm_swap_kib',
   'smaps_pss_kib','smaps_private_dirty_kib','mem_available_kib','mem_total_kib','buffer_bytes_limit',
  'memory_ceiling_bytes','max_connections','soft_nofile_limit','bytes_from_clients','bytes_from_upstreams',
  'process_id','process_started_at','process_generation','memory_accounted_allocations_bytes','buffer_bytes_current',
  'proxy_struct_bytes','connection_struct_bytes','retired_connection_struct_bytes','worker_pool_struct_bytes',
  'active_connections','fd_count','tls_objects','worker_pool_tls_objects','worker_pool_entries',
  'http_403','http_501','http_502','wss_failures'];
 const tgSample=row=>tgFields.map(name=>Object.prototype.hasOwnProperty.call(row,name)?row[name]:null);
 const fields=['mono_delta_s','catalog_bytes','at_delta_s','rss_kib','vm_data_kib','vm_swap_kib','smaps_rollup_status_code',
  'smaps_rollup_errno','smaps_rollup_kib','rss_anon_kib','http_bytes','snapshot_bytes','tracked_tcp_bytes','tracked_quic_bytes',
  'tracked_tls_bytes','tasks','workers_live','workers_result_pending','workers_join_pending','d2kc_epoch'];
 const encode=row=>fields.map(name=>Object.prototype.hasOwnProperty.call(row,name)?row[name]:null);
 const record=(i,overrides={})=>({mono_delta_s:i*60,catalog_bytes:i===1439?9625:8192+i,at_delta_s:i*60,rss_kib:41000+i,
  vm_data_kib:66000+i*2,vm_swap_kib:null,smaps_rollup_status_code:i>=1438?4:2,smaps_rollup_errno:null,
  smaps_rollup_kib:i>=1438?null:[40000+i,39000+i,22000+i*3,12000+i*5,0],rss_anon_kib:22000+i*3,
  http_bytes:i===1439?5529:4096+i,snapshot_bytes:2048+i*2,tracked_tcp_bytes:1024+i*3,tracked_quic_bytes:512+i*2,
  tracked_tls_bytes:256+i*4,tasks:4,workers_live:3,workers_result_pending:1,workers_join_pending:1,d2kc_epoch:0,...overrides});
 if(kind==='empty')return {schema:1,enabled:true,event_capacity:64,sample_capacity:120,events:[],samples:[],limit_transitions:[],
  memory_history:{capacity:1440,sample_interval_ms:60000,fields,time_base:[null,null],samples:[]},memory_details:[]};
 if(kind==='unavailable')return {schema:1,enabled:true,event_capacity:64,sample_capacity:120,events:[],
  samples:[{at:now,processes:[{name:'d2kc',pid:123,rss_kib:null,vm_data_kib:null,anon_kib:512}]}],
  memory_history:{capacity:1440,sample_interval_ms:60000,time_base:[now-60,1000],samples:[[0,0,null,null,null,1,13,null,512,null,null,null,null,null,null,0,0,0,0]]},
  memory_details:[{name:'d2kc',latest:{smaps_rollup_status:'unavailable',smaps_rollup_errno:13}}]};
 if(kind==='unsupported')return {schema:1,enabled:true,event_capacity:64,sample_capacity:120,events:[],
  samples:[{at:now,processes:[{name:'d2kc',pid:123,rss_kib:1100,vm_data_kib:2100,anon_kib:550}]}],
   memory_history:{capacity:1440,sample_interval_ms:60000,time_base:[now-60,1000],samples:[
    [0,0,1024,2048,null,4,null,null,512,8,16,4,1,2,3,2,1,0,0],
    [60,60,1100,2100,null,4,null,null,550,10,17,4,1,2,3,2,1,0,0]]},
  anomalies:[{kind:'unattributed-rss-growth',at:now,rss_delta_kib:1024,accounted_delta_kib:0,window_samples:10}],
   memory_details:[{name:'d2kc',latest:{smaps_rollup_status:'unsupported',smaps_rollup_errno:null,smaps_rollup_source:'unavailable',smaps_status:'not-read',smaps_errno:null}}]};
 if(kind==='fallback')return {schema:1,enabled:true,event_capacity:64,sample_capacity:120,events:[],
  samples:[{at:now,processes:[{name:'d2kc',pid:123,rss_kib:1024,vm_data_kib:2048,anon_kib:512}]}],
   memory_history:{capacity:1440,sample_interval_ms:60000,time_base:[now-60,1000],samples:[[0,0,1024,2048,null,4,2,[900,800,512,384,0],512,8,16,4,1,2,3,2,1,0,0]]},
   memory_details:[{name:'d2kc',latest:{smaps_rollup_status:'unsupported',smaps_rollup_errno:2,smaps_rollup_source:'smaps-fallback',smaps_rollup:{rss_kib:900,anonymous_kib:512,private_dirty_kib:384},smaps_status:'ok',smaps_errno:null}}]};
 if(kind==='legacy')return {schema:1,enabled:true,event_capacity:64,sample_capacity:120,events:[],
  samples:[{at:now,bindings:4,plans:2,boxes:1,processes:[{name:'d2kc',pid:77,rss_kib:8192,vm_data_kib:16384,anon_kib:4096}]}],
  memory_details:[{name:'d2kc',latest:{pid:77,rss_kib:8192,vm_data_kib:16384,smaps:{anonymous:{anonymous_kib:3072,private_dirty_kib:1024},heap:{anonymous_kib:2048,private_dirty_kib:1536},stack:{anonymous_kib:512,private_dirty_kib:256},other:{anonymous_kib:256,private_dirty_kib:128}}}}]};
 if(kind==='legacy_enoent')return {schema:1,enabled:true,event_capacity:64,sample_capacity:120,events:[],
  samples:[{at:now,bindings:1,plans:1,boxes:1,processes:[{name:'d2kc',pid:77,rss_kib:8192,vm_data_kib:16384,anon_kib:4096}]}],
  memory_details:[{name:'d2kc',latest:{pid:77,rss_kib:8192,vm_data_kib:16384,smaps_rollup_status:'unavailable',smaps_rollup_errno:2}}]};
 if(kind==='legacy_smaps_enoent')return {schema:1,enabled:true,event_capacity:64,sample_capacity:120,events:[],
  samples:[{at:now,processes:[{name:'d2kc',pid:77,rss_kib:8192,vm_data_kib:16384,anon_kib:4096}]}],
  memory_details:[{name:'d2kc',latest:{pid:77,smaps_rollup_status:'ok',smaps_rollup_source:'smaps_rollup',
   smaps_rollup:{rss_kib:8192,pss_kib:6144,anonymous_kib:4096,private_dirty_kib:2048,swap_kib:0},smaps_status:'unavailable',smaps_errno:2}}]};
 if(['units','short','time_mismatch','pid_change','sample_mismatch','legacy_history','legacy_no_fields'].includes(kind)){
  const count=kind==='short'?11:2, step=kind==='short'?60:600, raw=[];
  for(let i=0;i<count;i++){
   const epoch=kind==='pid_change'&&i===1?8:7;
   raw.push(record(i,{mono_delta_s:i*step,at_delta_s:i*step,smaps_rollup_status_code:4,smaps_rollup_kib:null,
    rss_kib:1024+i*1024,rss_anon_kib:512+i*512,vm_data_kib:4096+i*2048,
    catalog_bytes:i===count-1?9625:8192,http_bytes:i===count-1?5529:4096,
    snapshot_bytes:i===count-1?4096:2048,tracked_tcp_bytes:i===count-1?2048:1024,
    tracked_quic_bytes:i===count-1?2048:4096,tracked_tls_bytes:i===count-1?8192:0,d2kc_epoch:epoch}));
  }
  const firstAt=now-(count-1)*step, lastTime=1000+(count-1)*step;
  const currentPid=kind==='pid_change'?78:77;
  const sampleMono=kind==='time_mismatch'?lastTime-60:lastTime;
  const current=raw[raw.length-1];
  const memory={capacity:1440,sample_interval_ms:60000,time_base:[firstAt,1000],samples:raw.map(encode)};
  if(kind!=='legacy_no_fields')memory.fields=fields;
  if(kind==='legacy_history'||kind==='legacy_no_fields'){
   const oldFields=['at_delta_s','mono_delta_s','rss_kib','vm_data_kib','vm_swap_kib','smaps_rollup_status_code',
    'smaps_rollup_errno','smaps_rollup_kib','rss_anon_kib','catalog_kib','http_kib','snapshot_kib','tracked_tcp_kib',
    'tracked_quic_kib','tracked_tls_kib','tasks','workers_live','workers_result_pending','workers_join_pending'];
   if(kind==='legacy_history')memory.fields=oldFields;
   memory.samples=raw.map(r=>[r.at_delta_s,r.mono_delta_s,r.rss_kib,r.vm_data_kib,r.vm_swap_kib,r.smaps_rollup_status_code,
    r.smaps_rollup_errno,r.smaps_rollup_kib,r.rss_anon_kib,Math.ceil(r.catalog_bytes/1024),Math.ceil(r.http_bytes/1024),
    Math.ceil(r.snapshot_bytes/1024),Math.ceil(r.tracked_tcp_bytes/1024),Math.ceil(r.tracked_quic_bytes/1024),
    Math.ceil(r.tracked_tls_bytes/1024),r.tasks,r.workers_live,r.workers_result_pending,r.workers_join_pending]);
  }
  const sample={at:now,mono_ms:sampleMono*1000,catalog_bytes:current.catalog_bytes+(kind==='sample_mismatch'?1024:0),http_bytes:current.http_bytes,
   snapshot_bytes:current.snapshot_bytes,processes:[{name:'d2kc',pid:currentPid,rss_kib:current.rss_kib,
    vm_data_kib:current.vm_data_kib,anon_kib:current.rss_anon_kib,threads:5}]};
  return {schema:1,enabled:true,event_capacity:64,sample_capacity:120,samples:[sample],events:[],memory_history:memory,
   memory_details:[{name:'d2kc',latest:{pid:currentPid,rss_kib:current.rss_kib,smaps_rollup_status:'unsupported',
    smaps_rollup_errno:null,smaps_rollup_source:'unavailable'}}]};
 }
 const start=now-1439*60,history=[];
 for(let i=0;i<1440;i++)history.push(encode(record(i)));
 const current=record(1439);
  if(kind==='telegram_generation_change'||kind==='telegram_unavailable'||kind==='telegram_socket_unavailable'||kind==='telegram_socket_empty'||kind==='telegram_first_sample'||kind==='telegram_smaps_available'){
  const report=diagnosticFixture('full');
  if(kind==='telegram_generation_change'){
   const generation=report.telegram_diagnostics.memory_history.fields.indexOf('process_generation');
   report.telegram_diagnostics.memory_history.samples[2][generation]=9002;
   }else if(kind==='telegram_unavailable')report.telegram_diagnostics.latest.rss_kib=null;
   else if(kind==='telegram_socket_unavailable'||kind==='telegram_socket_empty'){
    report.telegram_diagnostics.collection_status='socket_unavailable';report.telegram_diagnostics.collection_failures=1;
    report.telegram_diagnostics.last_error=110;
    if(kind==='telegram_socket_empty'){
     report.telegram_diagnostics.latest=null;report.telegram_diagnostics.memory_history.samples=[];
    }
   }else if(kind==='telegram_first_sample'){
    report.telegram_diagnostics.memory_history.samples.splice(1);
   }else{
    const history=report.telegram_diagnostics.memory_history,pss=history.fields.indexOf('smaps_pss_kib');
    const dirty=history.fields.indexOf('smaps_private_dirty_kib');
    history.samples.forEach((sample,index)=>{sample[pss]=800+index*200;sample[dirty]=256+index*128;});
    Object.assign(report.telegram_diagnostics.latest,{smaps_rollup_status:'ok',smaps_pss_kib:1200,
     smaps_anonymous_kib:900,smaps_private_dirty_kib:640,smaps_swap_kib:2});
   }
  return report;
 }
 return {schema:1,enabled:true,telegram_enabled:true,event_capacity:64,limit_transition_capacity:32,sample_capacity:120,
  events:[{id:1,at:now,outcome:'failed'}],events_overwritten:6,samples_overwritten:2,
  limit_transitions_overwritten:1,memory_history_overwritten:20,
  limit_transitions:[{at:now-120,measurement_limit:2,measurement_slots:4,limit_reason:['cpu']},
   {at:now-60,measurement_limit:1,measurement_slots:1,limit_reason:['memory','conntrack']}],
  memory_history:{capacity:1440,sample_interval_ms:60000,fields,time_base:[start,500000],samples:history},
  samples:[{at:now,mono_ms:(500000+1439*60)*1000,boxes:3,bindings:8,plans:4,observations:12,
   snapshot_bytes:current.snapshot_bytes,catalog_bytes:current.catalog_bytes,workers_running:3,workers_live:3,workers_result_pending:1,workers_join_pending:1,
   worker_oldest_age_ms:12500,worker_oldest_type:'TCP',workers_started:40,workers_joined:36,
   worker_start_failures:2,worker_join_failures:1,http_failures:7,http_records_bytes:8192,
   http_queue_bytes:2048,http_failure_bytes:4096,http_record_limit_hits:2,http_queue_limit_hits:3,
   http_failure_limit_hits:1,http_failure_record_limit_hits:4,measurement_limit:1,measurement_slots:1,
   http_bytes:current.http_bytes,http_queue_bytes:2048,http_failure_bytes:4096,
   limit_reason:['memory','conntrack'],grow_pending:false,processes:[{name:'d2kc',pid:123,rss_kib:current.rss_kib,vm_data_kib:current.vm_data_kib,anon_kib:current.rss_anon_kib,threads:5}]}],
  http_storage_limits:{records_bytes:262144,queue_bytes:32768,failures_bytes:65536,failure_record_bytes:8192},
  memory_tracking:{enabled:true,coverage:'учитываются объекты, выделенные при включённом сборе',sites:[
   {id:'tls13.session',name:'TLS 1.3 session',location:'core/tls13.c:tls_connect_internal',live_bytes:1536,peak_bytes:2048,live_objects:1,created:4,destroyed:3,alloc_failures:0},
   {id:'quic.connection',name:'QUIC connection',location:'core/quicconn.c:d2k_qc_connect',live_bytes:3072,peak_bytes:6144,live_objects:1,created:6,destroyed:5,alloc_failures:0}]},
  madvise:{successes:10,failures:1,requested_bytes:65536,failed_requested_bytes:4096,last_errno:12,errno:[{code:12,count:1}],other_errno_count:0},
  diagnostic_write_failures:1,anomalies_overwritten:2,
  anomalies:[{kind:'unattributed-rss-growth',at:now,rss_delta_kib:1536,accounted_delta_kib:128,window_samples:10},
   {kind:'diagnostic-json-write-error',at:now,stage:'open-temp',error_code:13}],
  memory_details:[{name:'d2kc',latest:{smaps_rollup_status:'unsupported',smaps_rollup_source:'smaps-fallback',smaps_rollup_errno:2,smaps_status:'ok',smaps_errno:null,smaps_rollup:{rss_kib:42399,anonymous_kib:23439,private_dirty_kib:13439}}}],
  telegram_diagnostics:{enabled:true,last_sample_at:now,collection_failures:0,
   memory_history:{capacity:1440,sample_interval_ms:60000,fields:tgFields,
    time_base:[now-120,1000],samples:[
      tgSample({at_delta_s:0,mono_delta_s:0,rss_kib:1024,rss_hwm_kib:1024,rss_anon_kib:768,vm_data_kib:2048,
       vm_swap_kib:0,mem_available_kib:8192,mem_total_kib:131072,buffer_bytes_limit:65536,
      memory_ceiling_bytes:16777216,max_connections:128,soft_nofile_limit:1024,bytes_from_clients:1000,bytes_from_upstreams:500,
      process_id:77,process_started_at:now-3600,process_generation:9001,memory_accounted_allocations_bytes:4608,buffer_bytes_current:1024,
      proxy_struct_bytes:2048,connection_struct_bytes:1024,retired_connection_struct_bytes:0,worker_pool_struct_bytes:512,
      active_connections:1,fd_count:8,tls_objects:1,worker_pool_tls_objects:1,worker_pool_entries:1,
      http_403:1,http_501:1,http_502:0,wss_failures:1}),
      tgSample({at_delta_s:60,mono_delta_s:60,rss_kib:1280,rss_hwm_kib:1280,rss_anon_kib:896,vm_data_kib:2560,
       vm_swap_kib:0,mem_available_kib:7168,mem_total_kib:131072,buffer_bytes_limit:131072,
      memory_ceiling_bytes:33554432,max_connections:256,soft_nofile_limit:4096,bytes_from_clients:3000,bytes_from_upstreams:1500,
      process_id:77,process_started_at:now-3600,process_generation:9001,memory_accounted_allocations_bytes:6656,buffer_bytes_current:2048,
      proxy_struct_bytes:2048,connection_struct_bytes:2048,retired_connection_struct_bytes:0,worker_pool_struct_bytes:512,
      active_connections:2,fd_count:10,tls_objects:2,worker_pool_tls_objects:1,worker_pool_entries:1,
      http_403:2,http_501:1,http_502:0,wss_failures:2}),
      tgSample({at_delta_s:120,mono_delta_s:120,rss_kib:1536,rss_hwm_kib:1536,rss_anon_kib:1024,vm_data_kib:3072,
       vm_swap_kib:2,mem_available_kib:6144,mem_total_kib:131072,buffer_bytes_limit:131072,
      memory_ceiling_bytes:33554432,max_connections:256,soft_nofile_limit:4096,bytes_from_clients:6000,bytes_from_upstreams:3000,
      process_id:77,process_started_at:now-3600,process_generation:9001,memory_accounted_allocations_bytes:8704,buffer_bytes_current:3072,
      proxy_struct_bytes:2048,connection_struct_bytes:2048,retired_connection_struct_bytes:1024,worker_pool_struct_bytes:512,
      active_connections:2,fd_count:10,tls_objects:2,worker_pool_tls_objects:1,worker_pool_entries:2,
      http_403:2,http_501:2,http_502:1,wss_failures:3})]},
   latest:{rss_kib:1536,rss_hwm_kib:2048,rss_anon_kib:1024,vm_data_kib:3072,vm_swap_kib:0,
    smaps_pss_kib:null,smaps_anonymous_kib:null,smaps_private_dirty_kib:null,smaps_swap_kib:null,
    mem_available_kib:8192,mem_total_kib:131072,memory_accounted_allocations_bytes:8704,
    process_id:77,process_started_at:now-3600,process_generation:9001,smaps_rollup_status:'unsupported',smaps_rollup_errno:null,
    rss_minus_known_allocations_bytes:1564160,buffer_bytes_current:3072,buffer_bytes_peak:4096,
    buffer_bytes_limit:131072,memory_ceiling_bytes:33554432,active_connections:2,max_connections:256,
    active_wss_connections:1,max_wss_connections:16,client_queue_bytes:512,upstream_queue_bytes:256,
    client_queue_capacity_bytes:4096,upstream_queue_capacity_bytes:2048,ws_rx_capacity_bytes:8192,
    fd_count:10,soft_nofile_limit:4096,tls_objects:2,worker_pool_tls_objects:1,worker_pool_entries:2,
    worker_pool_capacity:4,proxy_struct_bytes:2048,connection_struct_bytes:2048,
    retired_connection_struct_bytes:1024,worker_pool_struct_bytes:512,
    ws_tx_memory_bytes:1024,mtproto_packet_capacity_bytes:16384,route_health:[],
    allocation_failures:0,buffer_budget_rejections:1,buffer_size_rejections:2,accept_limit_rejections:3,accept_fd_exhaustion:4,
    wss_read_pauses:5,wss_read_resumes:4,wss_paused_timeouts:1,wss_reads_paused:1,wss_oldest_pause_ms:1200,
    wss_attempts:12,wss_failures:3,wss_responses:8,cf_wss_responses:2,worker_pool_hits:4,worker_pool_misses:1,
    worker_pool_responses:3,client_response_latency_samples:5,client_response_latency_p50_us:42700,
    client_response_latency_p95_us:187000,failure_by_stage:{connect:2,handshake:1},
    dc_map_status:'fresh',dc_map_endpoint_count:4,dc_map_last_known_good:true,
    dc_map_refresh_attempts:3,dc_map_refresh_successes:2,dc_map_refresh_failures:1,
    dc_map_last_refresh_result:'http_error',dc_map_last_refresh_errno:104,dc_map_last_manifest_errno:null,
    dc_map_last_success_at:now-100,dc_map_last_failure_at:now-50,
    active_sessions:[{id:71,dc:2,is_media:true,direct_state:'selected',direct_transport:'cloudflare_proxy',
     fallback_state:'idle',fallback_transport:null,selected_transport:'cloudflare_proxy',first_response_latency_ms:420,
     client_queue_bytes:512,upstream_queue_bytes:256,client_queue_capacity_bytes:4096,upstream_queue_capacity_bytes:2048,
     age_ms:60000,no_progress_ms:3000,bytes_from_clients:307200,bytes_from_upstreams:153600,
     read_paused:false,stage:'first_wss_binary_response'}],problem_sessions:[]}}};
}
let ws,diagnosticsReply=null;
async function main(){
 let port;
 for(let i=0;i<100;i++){try{const activePort=fs.readFileSync(path.join(profile,'DevToolsActivePort'),'utf8').split('\n')[0];if(activePort){port=activePort;break}}catch{}await new Promise(r=>setTimeout(r,100))}
 if(!port)throw Error('Headless browser unavailable: '+chromeError);
 const tab=await(await fetch('http://127.0.0.1:'+port+'/json/new?about:blank',{method:'PUT'})).json();
 ws=new WebSocket(tab.webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j});
 let id=0;const pending=new Map(),exceptions=[],dialogs=[];
 ws.onmessage=e=>{const x=JSON.parse(e.data);if(x.id){const p=pending.get(x.id);pending.delete(x.id);x.error?p.reject(x.error):p.resolve(x.result)}
 else if(x.method==='Page.javascriptDialogOpening'){dialogs.push(x.params.message);call('Page.handleJavaScriptDialog',{accept:true})}
 else if(x.method==='Runtime.exceptionThrown')exceptions.push(x.params.exceptionDetails)
 else if(x.method==='Fetch.requestPaused'){
  if(x.params.request.url.includes('/api/diagnostics?status')){
   const report=diagnosticsReply||{};
   const flags={enabled:report.general_enabled===true||report.enabled===true,
    telegram_enabled:report.telegram_enabled===true};
   call('Fetch.fulfillRequest',{requestId:x.params.requestId,responseCode:200,
    responseHeaders:[{name:'Content-Type',value:'application/json; charset=utf-8'}],
    body:Buffer.from(JSON.stringify(flags)).toString('base64')});
  }else if(x.params.request.url.includes('/api/diagnostics?report'))call('Fetch.fulfillRequest',{requestId:x.params.requestId,responseCode:200,
   responseHeaders:[{name:'Content-Type',value:'application/json; charset=utf-8'}],
   body:Buffer.from(JSON.stringify(diagnosticsReply||{enabled:false})).toString('base64')});
  else call('Fetch.continueRequest',{requestId:x.params.requestId});}};
 const call=(method,params={})=>new Promise((resolve,reject)=>{pending.set(++id,{resolve,reject});ws.send(JSON.stringify({id,method,params}))});
 const evaluate=async(expression)=>{try{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value}catch(e){throw Error('Runtime.evaluate failed for '+expression+': '+(e?.message||JSON.stringify(e)))}};
 const wait=ms=>new Promise(r=>setTimeout(r,ms));
 const until=async(expr,msg,attempts=160)=>{for(let i=0;i<attempts;i++){if(await evaluate(expr))return;await wait(50)}throw Error(msg)};
 await call('Page.enable');await call('Runtime.enable');
 await call('Page.addScriptToEvaluateOnNewDocument',{source:`(()=>{
  const nativeFetch=window.fetch.bind(window);
  const dnsServices=[
   {protocol:'doh',host:'resolver-a.example.test',port:443,sni:'resolver-a.example.test',source:'https-dns-proxy',state:'direct_ok',status_reason:'DNS-ответ подтверждён без обхода'},
   {protocol:'dot',host:'resolver-b.example.test',port:853,sni:'resolver-b.example.test',source:'dnsproxy',state:'bypass_ok',status_reason:'DNS-ответ подтверждён с применённой стратегией'},
   {protocol:'doq',host:'resolver-c.example.test',port:853,sni:'resolver-c.example.test',source:'doqd',state:'failed',status_reason:'DNS-ответ не получен'},
   {protocol:'doh',host:'resolver-d.example.test',port:8443,sni:'resolver-d.example.test',source:'https-dns-proxy',state:'checking',status_reason:'Проверяется'}
  ];
  window.fetch=(input,init)=>nativeFetch(input,init).then(async response=>{
   const url=typeof input==='string'?input:input.url;
   if(new URL(url,location.href).pathname!=='/api/status')return response;
   const body=await response.clone().json();
   body.snapshot=body.snapshot||{};body.snapshot.dns_services=dnsServices;
   if(window.__searchLayoutFixture && body.knowledge)
    Object.assign(body.knowledge,window.__searchLayoutFixture);
   return new Response(JSON.stringify(body),{status:response.status,headers:{'Content-Type':'application/json'}});
  });
  const arc=CanvasRenderingContext2D.prototype.arc;
  const fillRect=CanvasRenderingContext2D.prototype.fillRect;
  window.__tgStartupParticles=[];
  window.__tgPacketSamples=[];
  CanvasRenderingContext2D.prototype.arc=function(x,y,r,...args){
   if(this.canvas?.classList.contains('tg-flow-canvas')&&this.globalCompositeOperation==='lighter'
      &&r>=1.8&&r<=2.2&&window.__tgStartupParticles.length<100)
    window.__tgStartupParticles.push({x,y,at:performance.now()});
   return arc.call(this,x,y,r,...args);
  };
  CanvasRenderingContext2D.prototype.fillRect=function(x,y,width,height){
   if(this.canvas?.classList.contains('tg-flow-canvas')&&this.globalCompositeOperation==='lighter'
      &&Math.abs(height-2.4)<0.1&&width>=3&&width<=12&&window.__tgPacketSamples.length<1000){
    const transform=this.getTransform();
    window.__tgPacketSamples.push({x:transform.e,y:transform.f,glow:this.shadowBlur});
   }
   return fillRect.call(this,x,y,width,height);
  };
 })()`});
 const out=process.env.D2K_CAPTURE_DIR;
 const panel=await require('./browser-c-fixture.cjs')(fixture);
 try{
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
  await call('Page.navigate',{url:panel.url});
  await until('document.querySelectorAll(".search").length===2','C API must populate the live searches');
  await until('!document.querySelector("#dns-services").hidden','discovered DNS services get their own pinned section');
  assert.equal(await evaluate('document.querySelector("#nav-dns-link").hidden'),false,'DNS section appears in panel navigation only after discovery');
  assert.equal(await evaluate('document.querySelector("#nav-dns").textContent'),'4','navigation shows all simultaneous DNS endpoints');
  assert.equal(await evaluate('document.querySelectorAll("#dns-services-list .dns-service").length'),4,'DoH, DoT and DoQ endpoints remain visible together');
  assert.equal(await evaluate('document.querySelectorAll("#dns-services-list .dns-protocol-doh").length'),2,'multiple DoH endpoints are supported');
  assert.equal(await evaluate('document.querySelectorAll("#dns-services-list .dns-protocol-dot").length'),1,'DoT is separately colored');
  assert.equal(await evaluate('document.querySelectorAll("#dns-services-list .dns-protocol-doq").length'),1,'DoQ is separately colored');
  assert.match(await evaluate('document.querySelector("#dns-services-summary").textContent'),/DoH 2 · DoT 1 · DoQ 1/,'simultaneous protocol combination is summarized');
  assert.match(await evaluate('document.querySelector("#dns-services-list").textContent'),/DNS-ответ подтверждён · прямая проверка/,'direct DNS success is explicit');
  assert.match(await evaluate('document.querySelector("#dns-services-list").textContent'),/DNS-ответ подтверждён с применённой стратегией/,'DNS success with an applied bypass is explicit');
  assert.match(await evaluate('document.querySelector("#dns-services-list").textContent'),/DNS-ответ не получен/,'failed DNS is explicit');
  assert.equal(await evaluate('document.querySelector("#dns-services-list .dns-service-state.dns-status-direct-ok")!==null'),true,'service state gets its own status color class');
  await evaluate('document.fonts.ready');
  assert.equal(await evaluate('document.fonts.check("700 24px Onest")'),true,'C CSP must load the bundled text face');
  try {
   await until('document.querySelector("#telegram-body .tg-flow-canvas")','C11 route canvas mounts from live stats');
  } catch(error) {
   console.error('Browser exceptions during Telegram startup:',JSON.stringify(exceptions));
   throw error;
  }
  await until('document.querySelector("[data-tg-accepted-count]").textContent==="77"',
   'fresh C11 stats update the visible Telegram connection counters');
  assert.equal(await evaluate('document.querySelectorAll("[data-tg-visual-mode]").length'),0,
   'prototype demonstration controls are not exposed in the live panel');
  assert.equal(await evaluate('document.querySelectorAll(".tg-flow-block").length'),0,
   'the prototype is shown without extra technical panels');
  assert.equal(await evaluate('document.querySelectorAll(".tg-flow-legend").length'),0,
   'пользовательские пояснения не заменяются техническими инструкциями');
  const help=await evaluate('(()=>{const d=document.querySelector(".tg-flow-help");return d?{open:d.open,summary:d.querySelector("summary")?.textContent.trim(),text:d.textContent}:null})()');
  assert.ok(help,'live Telegram card must include the route-state explainer');
  assert.equal(help.open,false,'the route-state explainer starts collapsed');
  assert.match(help.summary,/Как читать состояния/);
  assert.match(help.text,/Ответ Telegram подтверждён/);
  assert.doesNotMatch(help.text,/Прямой TCP/);
  assert.match(help.text,/DNS → TCP → TLS → WS → MTP/);
  assert.match(help.text,/маркер пульсирует/);
  assert.match(help.text,/пунктирное кольцо вращается/);
  assert.match(help.text,/оранжевая точка — запрос к Telegram, зелёная — ответ обратно/);
  assert.equal(await evaluate('!!document.querySelector("[data-tg-route-lock]")'),true,
   'Telegram card exposes a route-only switch');
  assert.equal(await evaluate('document.querySelector("[data-tg-route-select]").disabled'),true,
   'route selector is disabled while automatic routing is active');
  assert.equal(await evaluate('document.querySelectorAll("[data-tg-actions] [data-control]").length'),2,
   'only the real C11 controls are kept beside the prototype title');
  await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');
  await until('window.__tgStartupParticles.length>0','fresh real C11 route events animate on the first panel view');
  assert.ok(await evaluate('window.__tgStartupParticles.length>0'),
   'recent C11 events present in the first stats snapshot are not silently skipped');
  if(process.env.D2K_RECORD_TUNNEL){
   const playbackSessions=[
    {...fixture.telegramStats.active_sessions[0],stage:'first_wss_binary_response',
     telegram_response_seen:true,bytes_from_clients:10000,bytes_from_upstreams:8000,events:[]},
    {...fixture.telegramStats.active_sessions[1],stage:'first_wss_binary_response',
     fallback_state:'first_binary_response',selected_transport:'cloudflare_worker',
     telegram_response_seen:true,bytes_from_clients:10000,bytes_from_upstreams:8000,events:[]},
    {...fixture.telegramStats.active_sessions[2],stage:'first_wss_binary_response',
     telegram_response_seen:true,bytes_from_clients:10000,bytes_from_upstreams:8000,events:[]},
   ];
   const playbackBase={...fixture.telegramStats,active_connections:3,
    bytes_from_clients:32000,bytes_from_upstreams:24000,active_sessions:playbackSessions};
   panel.telegramStats(playbackBase);
   await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
   await until('document.querySelector("[data-tg-active-count]").textContent==="3"',
    'recording fixture reaches three confirmed C11 routes');
   await evaluate(`(()=>{
    const canvas=document.querySelector("#telegram-body .tg-flow-canvas");
    if(!canvas?.captureStream||!window.MediaRecorder)throw Error("Canvas WebM recording is unavailable");
    const stream=canvas.captureStream(30);
    const mimeType=["video/webm;codecs=vp8","video/webm"].find(type=>MediaRecorder.isTypeSupported(type));
    const recorder=new MediaRecorder(stream,mimeType?{mimeType}:undefined),chunks=[];
    window.__tgVideoResult=new Promise(resolve=>{
     recorder.ondataavailable=event=>{if(event.data.size)chunks.push(event.data)};
     recorder.onstop=()=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(",")[1]);
      reader.readAsDataURL(new Blob(chunks,{type:recorder.mimeType||"video/webm"}))};
    });
    recorder.start(100);
    window.__tgStopVideo=()=>{recorder.stop();stream.getTracks().forEach(track=>track.stop());return window.__tgVideoResult};
   })()`);
   for(let step=1;step<=5;step++){
    const sessions=playbackSessions.map((session,index)=>({...session,
     bytes_from_clients:session.bytes_from_clients+step*(index+1)*2048,
     bytes_from_upstreams:session.bytes_from_upstreams+step*(index+1)*3072}));
    panel.telegramStats({...playbackBase,accepted_connections:77+step,
     bytes_from_clients:32000+step*12288,bytes_from_upstreams:24000+step*18432,active_sessions:sessions});
    await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
    await until('document.querySelector("[data-tg-accepted-count]").textContent==="'+(77+step)+'"',
     'recording captures the next real-counter snapshot');
    await wait(180);
    if(step===3&&out){
     const image=await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").toDataURL("image/png").split(",")[1]');
     fs.writeFileSync(path.join(out,'telegram-packets.png'),Buffer.from(image,'base64'));
    }
   }
   await wait(1800);
   const video=await evaluate('window.__tgStopVideo()');
   fs.mkdirSync(path.dirname(process.env.D2K_RECORD_TUNNEL),{recursive:true});
   fs.writeFileSync(process.env.D2K_RECORD_TUNNEL,Buffer.from(video,'base64'));
   const samples=await evaluate('window.__tgPacketSamples');
   assert(samples.length>20,'confirmed byte deltas draw many glowing packets');
   assert(Math.min(...samples.map(sample=>sample.x))<500&&Math.max(...samples.map(sample=>sample.x))>700,
    'packets travel over the full selected route to and from Telegram DCs');
   assert(samples.some(sample=>sample.glow>=8),'request particles retain the prototype glow');
   console.log('Telegram animation WebM:',process.env.D2K_RECORD_TUNNEL,
    'bytes:',fs.statSync(process.env.D2K_RECORD_TUNNEL).size,'packet samples:',samples.length);
   panel.telegramStats(fixture.telegramStats);
   await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
   await until('document.querySelector("[data-tg-active-count]").textContent==="4"',
    'the browser fixture returns to its original C11 snapshot');
  }
  async function checkLayout(){
  // Раскладка на ширинах содержимого.
  for(const [name,width,height] of [['narrow',320,740],['phone-360',360,800],['phone',390,844],['compact-boundary',640,1020],['overlap-regression',649,1020],['small-tablet',650,1020],['chrome-report',678,1020],['mid-tablet',700,1020],['tablet',768,1024],['tablet-boundary',820,1020],['full-label-boundary',821,1020],['status-regression',854,1020],['large-tablet',971,1020],['nav-boundary',1080,1020],['laptop',1280,800],['wide',1920,1080]]){
   if(process.env.D2K_BASELINE_OVERLAP==='1'&&width!==649)continue;
   await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<600});
   await evaluate('scrollTo(0,0)');await wait(120);
   const mapDefaultOpen=await evaluate('(()=>{const m=document.querySelector(".tg-flow-map"),open=m.open;m.open=true;return open})()');
   const state=await evaluate(`(()=>{
    const buttons=[...document.querySelectorAll("#engine-actions [data-control]")];
    const brand=[...document.querySelectorAll(".mast-id .mark, .mast-id .wordmark")].map(x=>x.getBoundingClientRect());
    const range=document.createRange();range.selectNodeContents(document.querySelector(".mast-state-text"));
    const protectedRects=brand.concat([...range.getClientRects()]);
    const intersects=(a,b)=>a.left<b.right&&a.right>b.left&&a.top<b.bottom&&a.bottom>b.top;
    return {overflow:document.documentElement.scrollWidth>innerWidth,
     telegramCanvas:(()=>{const r=document.querySelector("#telegram-body .tg-flow-canvas")?.getBoundingClientRect();return r?{width:r.width,height:r.height,ratio:r.width/r.height}:null})(),
     bad:buttons.filter(x=>{const r=x.getBoundingClientRect();return r.left<0||r.right>innerWidth||r.top<0||r.height<44||r.width<44}).map(x=>x.dataset.control),
     overlaps:buttons.filter((x,i)=>protectedRects.some(r=>intersects(x.getBoundingClientRect(),r))||buttons.slice(i+1).some(y=>intersects(x.getBoundingClientRect(),y.getBoundingClientRect()))).map(x=>x.dataset.control)};
   })()`);
   console.log('layout',name,JSON.stringify(state));
   if(state.overflow)console.log('overflow by',await evaluate('[...document.body.querySelectorAll("*")].filter(x=>{const r=x.getBoundingClientRect();return r.width&&r.right>innerWidth+1}).map(x=>x.tagName+"."+(x.getAttribute("class")||"")+" right="+Math.round(x.getBoundingClientRect().right)+" style="+(x.getAttribute("style")||"")).slice(0,8)'));
   assert.equal(state.overflow,false,name+' horizontal overflow');
   assert.equal(mapDefaultOpen,width>640,name+' full route map disclosure matches the viewport');
   assert.equal(await evaluate('(()=>{const e=document.querySelector(".tg-flow");return e.scrollWidth<=e.clientWidth})()'),true,
    name+' Telegram card fits its viewport');
   const sourceRatio=state.telegramCanvas&&state.telegramCanvas.width<420?420/900:900/420;
   assert(state.telegramCanvas&&Math.abs(state.telegramCanvas.ratio-sourceRatio)<0.02,
    name+' Telegram diagram keeps the undistorted mobile or desktop composition');
   if(width===390){
    await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');
    await wait(100);
    await evaluate(`(()=>{const p=CanvasRenderingContext2D.prototype,draw=p.fillText;window.__tgMobileRouteLabels=[];window.__tgMobileOriginalFillText=draw;p.fillText=function(value,...args){if(this.canvas?.classList.contains("tg-flow-canvas")&&/^(Прокси Cloudflare|активен · 2)$/.test(String(value))){const t=this.getTransform();window.__tgMobileRouteLabels.push({text:String(value),y:t.f})}return draw.call(this,value,...args)}})()`);
    await wait(100);
    const labels=await evaluate('(()=>{const a=window.__tgMobileRouteLabels||[],i=a.findLastIndex(x=>x.text==="Прокси Cloudflare");return {title:a[i],state:a[i+1]}})()');
    await evaluate('CanvasRenderingContext2D.prototype.fillText=window.__tgMobileOriginalFillText;delete window.__tgMobileOriginalFillText');
    assert(labels.title&&labels.state&&Math.abs(labels.title.y-labels.state.y)>=10,
     'название мобильного маршрута и его состояние стоят в разных строках');
   }
   await evaluate('document.querySelector(".tg-flow-map").open='+String(mapDefaultOpen));
   if(out){const s=await call('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(out,'panel-'+name+'.png'),Buffer.from(s.data,'base64'))}
   assert.deepEqual(state.bad,[],name+' engine controls must be visible 44px targets in the masthead');
   assert.deepEqual(state.overlaps,[],name+' controls must not overlap the brand, engine status or one another');
   await evaluate('scrollTo(0,400)');await wait(120);
   const sticky=await evaluate(`(()=>{const mast=document.querySelector(".mast").getBoundingClientRect();const index=document.querySelector(".index").getBoundingClientRect();return {mastBottom:mast.bottom,indexTop:index.top};})()`);
   if(out){const s=await call('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(out,'panel-'+name+'-scrolled.png'),Buffer.from(s.data,'base64'))}
   console.log('sticky',name,JSON.stringify(sticky));
   assert(sticky.indexTop>=sticky.mastBottom-1,name+' sticky index must stay below the masthead');
   await evaluate('scrollTo(0,0)');await wait(120);
  }
  }
  async function checkSearchLayout(){
   const rects = `[...document.querySelectorAll(".mast, .index, [data-nav='families'], #engine-actions, #searches, .filter-bar, #families, #boxes, #telegram, #diagnostics")]
    .map(el=>{const r=el.getBoundingClientRect();return [r.x,r.y,r.width,r.height]})`;
   const setSearches=async(count)=>{
    const searches=Array.from({length:count},(_,i)=>({
     ...fixture.knowledge.searches[i<2?0:2], target:"discovered-"+i+".long-domain.example.test",
    }));
    const measurements={limit:16,active:Math.min(2,count),queued:Math.max(0,count-2),free_pct:30,cores:4};
    await evaluate(`window.__searchLayoutFixture=${JSON.stringify({searches,measurements})};
      document.dispatchEvent(new Event("visibilitychange"))`);
    await until(`document.querySelector("#nav-now").textContent===${JSON.stringify(count?String(count):"")}`,
     "search snapshot must appear in navigation");
   };
   for(const width of [1440,390,320]){
    await call("Emulation.setDeviceMetricsOverride",{width,height:900,deviceScaleFactor:1,mobile:width<600});
    await evaluate("scrollTo(0,0)");
    await setSearches(0);
    await wait(850);
    const before=await evaluate(rects);
    for(const count of [1,12,100,3,0]){
     await setSearches(count);
     assert.deepEqual(await evaluate(rects),before,width+"px: layout while rendering "+count+" searches");
     await wait(850);
     assert.deepEqual(await evaluate(rects),before,width+"px: layout after motion for "+count+" searches");
     assert.equal(await evaluate("document.documentElement.scrollWidth<=innerWidth"),true,width+"px: no horizontal page overflow");
     if(count===100){
      const scrolled=await evaluate(`(()=>{
       const list=document.querySelector("#searches"), pageY=scrollY;
       list.scrollTop=list.scrollHeight;
       const result=list.scrollTop>0&&scrollY===pageY;
       list.scrollTop=0;
       return result;
      })()`);
      assert.equal(scrolled,true,width+"px: long queue scrolls inside the results");
     }
    }
    console.log("search layout",width+"px","stable across empty, live and queued snapshots");
   }
   await call("Emulation.setDeviceMetricsOverride",{width:1440,height:900,deviceScaleFactor:1,mobile:false});
   await evaluate('delete window.__searchLayoutFixture;document.dispatchEvent(new Event("visibilitychange"))');
   await until('document.querySelector("#nav-now").textContent==="3"',"restore the original search fixture");
   await wait(850);
  }
  await checkSearchLayout();
  if(process.env.D2K_LAYOUT_ONLY){await checkLayout();return;}
  assert.match(await evaluate('document.querySelector("#now-title").textContent'),/Идёт 3 поиска/);
  assert.equal(await evaluate('document.querySelectorAll(".queue-list li").length'),1,'queued searches are listed compactly');
  assert.match(await evaluate('document.querySelector("#engine-state").textContent.trim()'),/^Движок работает, идёт подборрежим: применение$/,
    'panel process uptime must not be shown as engine uptime');

  // Данные из сети — только текст.
  assert.equal(await evaluate('document.body.textContent.includes("<img src=x onerror=alert(1)>")'),true,'network names are shown literally');
  assert.equal(await evaluate('[...document.images].some(i=>i.getAttribute("src")==="x")'),false,'network names never become elements');
  assert.deepEqual(dialogs,[]);

  // Семейство сворачивает покрытые имена, но не исключения и не другой IP-контекст.
  const rows=await evaluate('[...document.querySelectorAll(".bindings tbody tr")].map(r=>r.querySelector(".t").textContent+"|"+r.querySelector(".n").textContent)');
  assert.ok(rows.includes('skip.example.com|TLS 1.3 · IPv4'),'family exception stays visible');
  assert.ok(rows.includes('a.example.com|TLS 1.3 · IPv6'),'IPv6 context stays visible');
  assert.ok(!rows.includes('a.example.com|TLS 1.3 · IPv4'),'covered IPv4 name is folded into the family');
  assert.match(await evaluate('document.querySelector(".covered summary").textContent'),/1 цель покрыта/);

  // Коробки свёрнуты по умолчанию; C11 показывает активные сессии и реальные маршруты.
  assert.deepEqual(await evaluate('[...document.querySelectorAll(".crate")].map(c=>c.open)'),[false],'boxes start collapsed');
  assert.match(await evaluate('document.querySelector(".crate-label").textContent'),/4цели · 1 план/);
  await until('document.querySelector("#telegram-body").dataset.state==="connected"','C11 connected status renders in Telegram panel');
  assert.equal(await evaluate('document.querySelector("#telegram-body").dataset.state'),'connected');
  assert.equal(await evaluate('!!document.querySelector("#telegram-body .tg-flow-canvas")'),true,'C11 route canvas is present');
  assert.equal(await evaluate('document.querySelector("[data-tg-state-title]").textContent'),'Ответ Telegram подтверждён');
  assert.match(await evaluate('document.querySelector("[data-tg-last-success]").textContent'),/DC2 · Прокси Cloudflare/);
  assert.match(await evaluate('document.querySelector("[data-tg-last-warning]").textContent'),/WebSocket · DC4 · Прокси Cloudflare/);
  assert.equal(await evaluate('document.querySelectorAll("[data-tg-routes] li").length'),2,
   'the compact route summary keeps all configured route states visible');
  assert.equal(await evaluate('document.querySelectorAll("[data-tg-dcs] li").length'),6,
   'the compact DC summary includes five DCs and the unknown session');
  assert.equal(await evaluate('document.querySelector(".tg-flow-map").open'),true,'desktop keeps the full route map open');
  assert.equal(await evaluate('document.querySelector(".tg-flow-metrics").compareDocumentPosition(document.querySelector(".tg-route-diagnostics"))&Node.DOCUMENT_POSITION_FOLLOWING ? true : false'),true,
   'metrics follow the status rows before the route and DC summary');

  // Telegram: маршруты, DC, media и состояния совпадают со снимком C11.
  await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');
  const shots=process.env.D2K_TUNNEL_SHOTS;
  if(shots)fs.mkdirSync(shots,{recursive:true});
  const tunnelShot=async name=>{if(!shots)return;
   const b=await evaluate('(()=>{const r=document.querySelector("#telegram-body").getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height}})()');
   const s=await call('Page.captureScreenshot',{format:'png',clip:{...b,scale:2}});fs.writeFileSync(path.join(shots,name+'.png'),Buffer.from(s.data,'base64'))};
  const tunnelViewportShot=async name=>{if(!shots)return;
   const s=await call('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(shots,name+'.png'),Buffer.from(s.data,'base64'))};
  const tunnelState=async st=>{panel.telegram(st);await until('document.querySelector("#telegram-body").dataset.state==="'+st+'"','tunnel must reach '+st)};
  await evaluate('(()=>{window.tgFlowCanvas=document.querySelector("#telegram-body .tg-flow-canvas");return true})()');
  const flowCanvasSize=await evaluate('(()=>{const r=document.querySelector("#telegram-body .tg-flow-canvas").getBoundingClientRect();return {width:r.width,height:r.height}})()');
  assert.ok(Math.abs(flowCanvasSize.width / flowCanvasSize.height - 900 / 420) < 0.01,
    'canvas keeps the source prototype 900×420 composition ratio');
  assert.equal(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").dataset.state'),'mixed','C11 sessions show active and connecting route states');
  assert.match(await evaluate('document.querySelector("#tg-flow-caption").textContent'),/Несколько DC · media 2/);
  assert.equal(await evaluate('document.querySelectorAll(".tg-flow-metric").length'),7,
    'six prototype metrics plus the current confirmed-session count are shown');
  assert.equal(await evaluate('document.querySelector("[data-tg-accepted-count]").textContent'),'77');
  assert.equal(await evaluate('document.querySelector("[data-tg-confirmed-count]").textContent'),'5',
    'cumulative Telegram responses stay separate from current sessions');
  assert.equal(await evaluate('document.querySelector("[data-tg-confirmed-active]").textContent'),'1',
    'current confirmed sessions match the active route rows');
  assert.equal(await evaluate('document.querySelector("[data-tg-active-count]").textContent'),'4');
  assert.match(await evaluate('document.querySelector("[data-tg-process-start]").textContent'),/Процесс с/);
  assert.equal(await evaluate('document.querySelector("[data-tg-latency]").textContent'),'43 / 187 мс',
    'C11 microseconds are shown as milliseconds');
  panel.telegramStats({...fixture.telegramStats,client_response_latency_samples:0,
   client_response_latency_p50_us:0,client_response_latency_p95_us:0});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("[data-tg-latency]").textContent==="—"',
    'latency without samples is unavailable, not zero');
  panel.telegramStats(fixture.telegramStats);
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("[data-tg-latency]").textContent==="43 / 187 мс"',
    'latency returns when samples are available');
  assert.equal(await evaluate('document.querySelector("[data-tg-wss]").textContent'),'2 / 12');
  assert.equal(await evaluate('document.querySelector("[data-tg-traffic]").textContent'),'1,2 КБ / 980 Б');
  assert.match(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Клиент → d2o.*Ответ Telegram подтверждён/);
  assert.match(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/отказ на воротах TLS.*пауза 1 маршрута/,
    'failure gate and live route cooldown are announced from C11 statistics');
  assert.doesNotMatch(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Резервный TCP/,
    'unused routes are omitted from the diagram');
  assert.doesNotMatch(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/d2ktg C11/);
  assert.doesNotMatch(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Прямой TCP|Прямой WSS/);
  assert.equal(await evaluate('window.tgFlowCanvas===document.querySelector("#telegram-body .tg-flow-canvas")'),true,'route canvas is mounted once');
  await evaluate('document.querySelector("[data-control=telegram-workers]").focus()');
  panel.telegramStats({...fixture.telegramStats,accepted_connections:78,connections_started:78});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("[data-tg-accepted-count]").textContent==="78"','Telegram metrics refresh from the existing status poll');
  assert.equal(await evaluate('document.activeElement.getAttribute("data-control")'),'telegram-workers',
   'a stats refresh keeps focus on the same Telegram action');
  panel.telegramStats(fixture.telegramStats);
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("[data-tg-accepted-count]").textContent==="77"','original Telegram metrics return');
  await wait(700);
  await tunnelShot('1-connected');
  if(shots){
   await tunnelViewportShot('telegram-desktop');
   await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
   await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');await wait(200);
   await tunnelViewportShot('telegram-mobile');
   await call('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
   await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');await wait(120);
  }

  // Подтверждённый ответ идёт от Telegram DC обратно к клиенту.
  panel.telegramStats({...fixture.telegramStats,active_connections:0,active_sessions:[]});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("#telegram-body .tg-flow-canvas").dataset.state==="cooling"','empty C11 snapshot preserves a live route cooldown');
  assert.equal(await evaluate('document.querySelector("[data-tg-active-count]").textContent'),'0',
    'cooldown is shown without inventing active sessions');
  panel.telegramStats({...fixture.telegramStats,active_connections:0,active_sessions:[],route_cooldowns:[]});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("#telegram-body .tg-flow-canvas").dataset.state==="idle"','expired route cooldown clears from C11 stats');
  await wait(await evaluate('Math.max(window.D2kTelegramFlow.motionProfile.responseDurationMs,1400)+50'));
  const sessionBeforeResponse={...fixture.telegramStats.active_sessions[0],telegram_response_seen:false,events:[]};
  panel.telegramStats({...fixture.telegramStats,active_connections:1,active_sessions:[sessionBeforeResponse]});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("[data-tg-active-count]").textContent==="1"','C11 reports a new session before its first response');
  await until('document.querySelector("#telegram-body .tg-flow-canvas").dataset.state==="active"','selected route is active before response confirmation');
  await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").scrollIntoView({block:"center"})');
  await wait(150);
  await evaluate('(()=>{const canvas=document.querySelector("#telegram-body .tg-flow-canvas");const proto=CanvasRenderingContext2D.prototype;const arc=proto.arc,lineTo=proto.lineTo,stroke=proto.stroke,beginPath=proto.beginPath,raf=window.requestAnimationFrame;window.__tgResponseXs=[];window.__tgLighterArcs=0;window.__tgAnimationFrames=0;window.__tgEcgSamples=0;window.__tgUnconfirmedGreenTrafficStrokes=0;window.__tgGreenDirectRouteStrokes=0;window.__tgOriginalArc=arc;window.__tgOriginalLineTo=lineTo;window.__tgOriginalStroke=stroke;window.__tgOriginalBeginPath=beginPath;window.requestAnimationFrame=function(cb){return raf.call(window,ts=>{window.__tgAnimationFrames++;cb(ts)})};proto.arc=function(x,y,r,...args){if(this.canvas===canvas&&this.globalCompositeOperation==="lighter"){window.__tgLighterArcs++;if(r>=1.8&&r<=2.2)window.__tgResponseXs.push(x)}return arc.call(this,x,y,r,...args)};proto.beginPath=function(...args){if(this.canvas===canvas)this.__tgDirectLanePath=false;return beginPath.apply(this,args)};proto.lineTo=function(x,y,...args){if(this.canvas===canvas&&Math.abs(y-148)<0.01)this.__tgDirectLanePath=true;if(this.canvas===canvas&&this.globalCompositeOperation==="source-over"&&x>=100&&x<=266&&Math.abs(y-210)>0.1)window.__tgEcgSamples++;return lineTo.call(this,x,y,...args)};proto.stroke=function(...args){if(this.canvas===canvas){const green=this.strokeStyle.includes("143, 220, 178");if(green&&this.getLineDash().length&&this.lineDashOffset!==0)window.__tgUnconfirmedGreenTrafficStrokes++;if(this.__tgDirectLanePath&&green)window.__tgGreenDirectRouteStrokes++}return stroke.apply(this,args)};return true})()');
  await wait(120);
  assert.equal(await evaluate('window.__tgResponseXs.length'),0,'upstream_ready does not invent a Telegram response pulse');
  assert.equal(await evaluate('window.__tgUnconfirmedGreenTrafficStrokes'),0,
    'неподтверждённый upstream не рисуется движущимися зелёными пакетами');
  assert.equal(await evaluate('window.__tgGreenDirectRouteStrokes'),0,
    'маршрут остаётся оранжевым до подтверждённого ответа Telegram');
  assert.equal(await evaluate('window.__tgEcgSamples'),0,'the client ECG stays quiet before a confirmed MTProto response');
  await evaluate('window.__tgResponseStartedAt=performance.now()');
  const confirmedSession={...sessionBeforeResponse,telegram_response_seen:true,
   events:[{sequence:1,branch:'direct',transport:'cloudflare_proxy',state:'first_binary_response'}]};
  panel.telegramStats({...fixture.telegramStats,active_connections:1,active_sessions:[confirmedSession]});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label").includes("Ответ Telegram подтверждён")','confirmed response reaches the live scene accessibility state');
  await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").scrollIntoView({block:"center"})');
  await wait(180);
  assert.ok(await evaluate('window.__tgGreenDirectRouteStrokes>0'),
    'маршрут становится зелёным только после подтверждённого ответа');
  try { await until('window.__tgResponseXs.length>3','confirmed C11 response is animated after observation'); }
  catch(error) {
    console.log('response animation diagnostic',JSON.stringify(await evaluate('(()=>{const c=document.querySelector("#telegram-body .tg-flow-canvas"),r=c.getBoundingClientRect();return {samples:window.__tgResponseXs.length,lighterArcs:window.__tgLighterArcs,frames:window.__tgAnimationFrames,hidden:document.hidden,reduced:matchMedia("(prefers-reduced-motion: reduce)").matches,canvasState:c.dataset.state,aria:c.getAttribute("aria-label"),canvasTop:r.top,viewport:innerHeight,scrollY,stats:window.D2kTelegramFlow.summarizeTelegramFlow('+JSON.stringify(confirmedSession)+').sessions[0]?.telegram_response_seen}})()')));
    throw error;
  }
  await wait(await evaluate('window.D2kTelegramFlow.motionProfile.responseDurationMs*0.35'));
  const responseMovement=await evaluate('({first:window.__tgResponseXs[0],last:window.__tgResponseXs.at(-1),count:window.__tgResponseXs.length})');
  assert.ok(responseMovement.count>3,'confirmed response is animated');
  assert.ok(responseMovement.first>responseMovement.last+20,'подтверждённый ответ движется от DC к клиенту');
  await wait(await evaluate('Math.max(0,window.D2kTelegramFlow.motionProfile.responseDurationMs-(performance.now()-window.__tgResponseStartedAt)+80)'));
  await until('window.__tgEcgSamples>0','the client ECG pulses when the confirmed response reaches the client');
  await evaluate('CanvasRenderingContext2D.prototype.arc=window.__tgOriginalArc;CanvasRenderingContext2D.prototype.lineTo=window.__tgOriginalLineTo;CanvasRenderingContext2D.prototype.stroke=window.__tgOriginalStroke;CanvasRenderingContext2D.prototype.beginPath=window.__tgOriginalBeginPath;delete window.__tgOriginalArc;delete window.__tgOriginalLineTo;delete window.__tgOriginalStroke;delete window.__tgOriginalBeginPath');

  const staleSceneStats={...fixture.telegramStats,active_connections:1,active_sessions:[confirmedSession]};
  await evaluate(`document.querySelector("#telegram-body").__tgUi.scene.__flow.update(${JSON.stringify(staleSceneStats)},true)`);
  assert.equal(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").dataset.state'),'stale',
    'устаревший снимок получает отдельное состояние сцены');
  assert.match(await evaluate('document.querySelector("#tg-flow-caption").textContent'),/Данные маршрутов устарели/);
  await evaluate(`document.querySelector("#telegram-body").__tgUi.scene.__flow.update(${JSON.stringify(staleSceneStats)},false)`);
  panel.telegramStats(staleSceneStats);
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');

  // Свежий отказ всех WSS-маршрутов не должен выглядеть как активное подключение из-за старого ответа.
  await evaluate('(()=>{const canvas=document.querySelector("#telegram-body .tg-flow-canvas");const proto=CanvasRenderingContext2D.prototype;const moveTo=proto.moveTo;window.__tgIncomingPathDraws=0;window.__tgOriginalMoveTo=moveTo;proto.moveTo=function(x,y){if(this.canvas===canvas&&this.globalCompositeOperation==="source-over"&&x===70&&y===210)window.__tgIncomingPathDraws++;return moveTo.call(this,x,y)};return true})()');
  panel.telegram('local');
  panel.telegramStats({...fixture.telegramStats,active_connections:0,active_sessions:[],
   route_cooldowns:[],last_failure_age_ms:100,last_success_age_ms:10000});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("#telegram-body").dataset.state==="unavailable"','new WSS failure must replace stale connected state');
  await evaluate('window.__tgIncomingPathDraws=0');
  await wait(50);
  assert.equal(await evaluate('window.__tgIncomingPathDraws'),0,'при нуле активных соединений схема не рисует линию клиент → d2o');
  await evaluate('CanvasRenderingContext2D.prototype.moveTo=window.__tgOriginalMoveTo;delete window.__tgOriginalMoveTo');
  assert.equal(await evaluate('document.querySelector("[data-tg-state-title]").textContent'),'Последняя попытка завершилась ошибкой');
  assert.equal(await evaluate('document.querySelector("[data-tg-state-lamp]").dataset.tone'),'bad');
  assert.match(await evaluate('document.querySelector("#tg-flow-caption").textContent'),/Последняя ошибка: WebSocket · DC4 · Прокси Cloudflare/);
  assert.match(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Прокси Cloudflare — отказ: 1/);
  assert.doesNotMatch(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Прямой WSS|Cloudflare Worker|Резервный TCP/,
    'failure view names only the route that actually failed');

  panel.telegram('connecting');
  panel.telegramStats({...fixture.telegramStats,active_connections:0,active_sessions:[],route_cooldowns:[],
   last_failure_age_ms:100,last_success_age_ms:10000});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("#telegram-body").dataset.state==="unavailable"',
   'a recent route failure stays visible while the service status is connecting');
  assert.equal(await evaluate('document.querySelector("[data-tg-state-lamp]").dataset.tone'),'bad');

  // Сбой выбора маршрута не приписывает отказ прямому WSS и старый сбой остаётся историей.
  panel.telegram('local');
  panel.telegramStats({...fixture.telegramStats,active_connections:0,active_sessions:[],route_cooldowns:[],
   last_failure_route:0,last_failure_stage:7,last_failure_dc:0,last_failure_age_ms:100,
   last_success_age_ms:10000});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("[data-tg-last-warning]").textContent.includes("Маршрут не выбран")',
   'an unavailable route plan replaces the previous WebSocket warning');
  assert.match(await evaluate('document.querySelector("[data-tg-last-warning]").textContent'),/настройка маршрута.*DC неизвестен.*Маршрут не выбран/i);
  assert.equal(await evaluate('[...document.querySelectorAll("[data-tg-routes] li")].some(x=>/Прямой WSS.*Отказ/.test(x.textContent))'),false,
   'an empty route plan does not invent a direct WSS attempt');
  panel.telegramStats({...fixture.telegramStats,active_connections:0,active_sessions:[],route_cooldowns:[],
   last_failure_route:0,last_failure_stage:7,last_failure_dc:0,last_failure_age_ms:120000,
   last_success_age_ms:10000});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("#telegram-body").dataset.state==="idle"','an old route failure expires from current status');
  assert.equal(await evaluate('document.querySelector("[data-tg-state-title]").textContent'),'Нет активных сессий');
  assert.match(await evaluate('document.querySelector("[data-tg-last-warning]").textContent'),/2 мин 00 с назад/,
   'expired failures remain visible with their age as history');
  panel.telegram('connected');
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("#telegram-body").dataset.state==="connected"','new confirmed C11 snapshot restores connected state');

  // Worker-ы редактируются в тематическом диалоге и перезапускают только C11.
  await evaluate('document.querySelector("[data-control=telegram-workers]").click()');
  await until('document.querySelector(".tg-worker-dialog").open','Worker list opens in its own dialog');
  await until('document.querySelector("[data-worker-note]").textContent.includes("hostname")','Worker settings are loaded');
  await evaluate('(()=>{const i=document.querySelector("[data-worker-input]");i.value="my-worker.example.com";document.querySelector("[data-worker-add]").click()})()');
  assert.match(await evaluate('document.querySelector("[data-worker-list]").textContent'),/my-worker.example.com/);
  await evaluate('document.querySelector("[data-worker-save]").click()');
  await panel.waitFor('telegram-restart');
  await until('!document.querySelector(".tg-worker-dialog").open','Saving Workers closes the dialog after C11 restart is accepted');
  const workerSettings=await(await fetch(panel.url+'api/telegram/workers')).json();
  assert.deepEqual(workerSettings.domains,['my-worker.example.com'],'Worker hostname is persisted in C11 config');
  assert.equal(panel.seen('engine-restart'),false,'editing Workers does not restart d2o');
  await tunnelState('stopped');
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await tunnelShot('2-stopped');
  assert.equal(await evaluate('document.querySelector("[data-tg-active-count]").textContent'),'—',
   'stopped C11 does not present unavailable live statistics as zero');
  assert.equal(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").dataset.state'),'unavailable',
   'отсутствующий stats socket отображается как недоступные данные');
  assert.match(await evaluate('document.querySelector("#tg-flow-caption").textContent'),/Статистика маршрутов недоступна/);
  await tunnelState('connecting');
  await tunnelShot('3-connecting');
  await tunnelState('connected');
  assert.equal(await evaluate('window.tgFlowCanvas===document.querySelector("#telegram-body .tg-flow-canvas")'),true,'polling and service states preserve the same route canvas');
  await tunnelShot('4-connected');
  await tunnelState('connected');

  // GSAP загружен с роутера под CSP; коробка открывается сценой и закрывается обратно.
  assert.equal(await evaluate('typeof gsap==="object"&&typeof Flip==="function"&&document.documentElement.classList.contains("has-gsap")'),true,'GSAP must load from the panel itself');
  await evaluate('document.querySelector(".crate-lid").click()');
  await until('document.querySelector(".crate").open&&!gsap.isTweening(document.querySelector(".crate-body"))','crate opens through its timeline');
  await wait(400);
  assert.equal(await evaluate('getComputedStyle(document.querySelector(".crate-body")).height!=="0px"'),true,'opened crate shows its contents');
  await evaluate('document.querySelector(".crate-lid").click()');
  await until('!document.querySelector(".crate").open','crate closes after its reverse timeline');
  assert.equal(await evaluate('document.querySelector(".crate-body").getAttribute("style")||""'),'','animation leaves no inline styles behind');

  // Бирка семейства ведёт к коробке с её планом: прокрутка и раскрытие.
  assert.equal(await evaluate('document.querySelectorAll(".ftag-wrap").length'),2,'families are drawn as tags');
  assert.equal(await evaluate('document.querySelectorAll(".ftag-wrap")[1].querySelector(".ftag-stamp").textContent'),
   'Семейство подтверждено · 5 доменов','family confirmation stays visible before datapath ACK');
  assert.equal(await evaluate('document.querySelectorAll(".ftag-wrap")[1].querySelector(".ftag-install").textContent'),
   'Ожидает установки общего правила','install state is independent from family confirmation');
  assert.equal(await evaluate('document.querySelectorAll(".ftag-wrap")[1].querySelector(".ftag-fold-text").textContent'),
   '5 подтверждённых доменов · без плана 1','expanded evidence count comes from the current evidence list');
  await evaluate('document.querySelectorAll(".ftag-wrap")[1].querySelector(".ftag-fold").click()');
  assert.equal(await evaluate('document.querySelectorAll(".ftag-wrap")[1].querySelectorAll(".ftag-tree li").length'),6,
   'all five current confirmations and the separate exception are listed');
  await evaluate('document.querySelectorAll(".ftag-wrap")[1].querySelector(".ftag-box").click()');
  await until('document.querySelector(".crate").open&&!gsap.isTweening(window)','family tag link opens its box');
  await evaluate('document.querySelector(".crate-lid").click()');
  await until('!document.querySelector(".crate").open','box closes again');
  fixture.knowledge.groups[1].install_state='active';
  fixture.knowledge.groups[1].active=true;
  await until('document.querySelectorAll(".ftag-wrap")[1].querySelector(".ftag-install")?.textContent==="Общее правило активно"',
   'positive datapath ACK is shown as active');
  fixture.knowledge.groups[1].install_state='removing';
  fixture.knowledge.groups[1].active=false;
  fixture.knowledge.groups[1].possibly_active=true;
  fixture.knowledge.groups[1].remove_pending=true;
  fixture.knowledge.groups[1].exception_install_state='pending';
  await until('document.querySelectorAll(".ftag-wrap")[1].querySelector(".ftag-install")?.textContent.includes("правило может оставаться активным")',
   'pending exception warns that the old family rule may still apply');
  fixture.knowledge.groups[1].install_state='retrying';
  fixture.knowledge.groups[1].install_reason='ack_timeout';
  fixture.knowledge.groups[1].active=false;
  fixture.knowledge.groups[1].remove_pending=false;
  fixture.knowledge.groups[1].possibly_active=false;
  fixture.knowledge.groups[1].exception_install_state='none';
  await until('document.querySelectorAll(".ftag-wrap")[1].querySelector(".ftag-install")?.textContent.includes("датапат не ответил")',
   'lost ACK shows an automatic retry and its reason');
  fixture.knowledge.groups[1].install_state='rejected';
  fixture.knowledge.groups[1].install_reason='bad_plan';
  await until('document.querySelectorAll(".ftag-wrap")[1].querySelector(".ftag-install")?.textContent.includes("план не принят")',
   'permanent datapath refusal shows its specific reason');
  assert.equal(await evaluate('document.querySelectorAll(".ftag-wrap")[1].querySelector(".ftag-stamp").textContent'),
   'Семейство подтверждено · 5 доменов','installation failures do not revoke family evidence');
  assert.equal(await evaluate('!!document.querySelector(".index-marker")&&getComputedStyle(document.querySelector(".index-marker")).display'),'block','navigation marker is present');
  assert.match(await evaluate('document.title'),/^(● )?D2K — Движок работает, идёт подбор$/,'title carries the engine state and no theme name');
  assert.equal(await evaluate('document.body.textContent.includes("Ведомость")'),false,'the theme name is not shown in the interface');

  // Опрос не сбрасывает раскрытые подробности, фокус и фильтр.
  await evaluate('document.querySelector(".plan").open=true');
  await evaluate('(()=>{const button=document.querySelector("[data-control=restart]");button.focus();window.restartBefore=button;return true})()');
  const polls='performance.getEntriesByType("resource").filter(e=>new URL(e.name).pathname==="/api/status").length';
  const before=await evaluate(polls);
  /* В простое опрос раз в 6 с (PR #18): два опроса — до 12 с, ждём 15. */
  for(let i=0;;i++){if(await evaluate(polls+'>='+(before+2)))break;if(i>=300)throw Error('panel must keep polling');await wait(50)}
  assert.equal(await evaluate('document.querySelector(".plan").open'),true,'open plan survives polling');
  assert.equal(await evaluate('document.activeElement===window.restartBefore'),true,'focused control is not replaced by a poll');
  await evaluate('(()=>{const i=document.querySelector("#filter");i.value="skip";i.dispatchEvent(new Event("input"))})()');
  assert.match(await evaluate('document.querySelector("#filter-count").textContent'),/1 цель/);
  assert.equal(await evaluate('document.querySelector(".crate").open'),true,'a box with filter matches opens itself');
  await evaluate('(()=>{const i=document.querySelector("#filter");i.value="";i.dispatchEvent(new Event("input"))})()');

  // Шкала фаз совпадает с этапом оригинала.
  assert.equal(await evaluate('document.querySelector(".search .track-step[data-state=now]").textContent'),'Распознаём');

  // Карточка этапа «Распознаём»: последний вопрос и счётчик зондов, без устаревшего источника.
  assert.equal(await evaluate('document.querySelector(".search .search-question").textContent'),'Вопрос коробке: принимает ли ответ на усечённое приветствие');
  assert.equal(await evaluate('document.querySelector(".search .search-question").hidden'),false);
  assert.match(await evaluate('document.querySelector(".search").textContent'),/5 зондов/);
  assert.doesNotMatch(await evaluate('document.querySelector(".search").textContent'),/выведен из замера/);
  assert.equal(await evaluate('[...document.querySelectorAll(".search")].filter(x=>!x.querySelector(".search-question").hidden).length'),1,'question only on the classifier card');

  await checkLayout();
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});

  // Остановка требует подтверждения; все шесть команд доходят до службы.
  await evaluate('document.querySelector("[data-control=stop]").click()');
  assert.equal(await evaluate('document.querySelector("[data-control=stop]").textContent'),'Остановить движок?','stop needs an explicit second press');
  await evaluate('document.querySelector("[data-control=cancel]").click()');

  // ОЧИСТКА ПОДОБРАННОГО СПРАШИВАЕТ ДИАЛОГОМ, И ОТКАЗ ЕЁ ОТМЕНЯЕТ.
  // Одно нажатие не должно доходить до службы: операция необратима, а текст
  // предупреждения обязан быть на экране и называть, что именно исчезнет.
  await until('!!document.querySelector("[data-control=clear-found]:not([disabled])")','clear-found control must be offered');
  await evaluate('document.querySelector("[data-control=clear-found]").click()');
  assert.equal(await evaluate('document.querySelector("#ask").open'),true,'clearing must ask in a dialog');
  const askText=await evaluate('document.querySelector("#ask-text").textContent');
  for(const must of ['Восстановить нельзя','подтверждённые планы','Точно очищаем?'])
   assert.ok(askText.includes(must),'the warning must say "'+must+'", got: '+askText);
  assert.equal(await evaluate('document.activeElement.dataset.ask'),'no','focus must start on the refusal, not on the irreversible button');
  await evaluate('document.querySelector("#ask [data-ask=no]").click()');
  assert.equal(await evaluate('document.querySelector("#ask").open'),false,'refusing must close the dialog');
  assert.equal(panel.seen('clear-found'),false,'a refused confirmation must not reach the service');

  for(const [action,command,presses] of [['stop','engine-stop',2],['start','engine-start',1],['restart','engine-restart',1],['clear-found','clear-found',1],['telegram-disable','telegram-disable',1],['telegram-enable','telegram-enable',1]]){
   await until('!!document.querySelector("[data-control='+action+']:not([disabled])")',action+' control must become available');
   for(let i=0;i<presses;i++)await evaluate('document.querySelector("[data-control='+action+']").click()');
   if(action==='clear-found'){
    assert.equal(await evaluate('document.querySelector("#ask").open'),true,'clearing must ask every time, not only once');
    await evaluate('document.querySelector("#ask [data-ask=yes]").click()');
   }
   await panel.waitFor(command);
   if(action==='stop'){
    await until('/остановлен/.test(document.querySelector("#now-title").textContent)','stopped engine must be stated',400);
    const s=await(await fetch(panel.url+'api/status')).json();
    assert.equal(s.snapshot.telegram_enabled,true,'stopping the engine leaves the tunnel alone');
   }
   if(action==='telegram-disable'){
    await until('document.querySelector("#telegram-body").dataset.state==="stopped"','tunnel drawing must show the stopped state');
    await until('!!document.querySelector("[data-control=telegram-enable]")','tunnel must offer enabling after disable');
    const s=await(await fetch(panel.url+'api/status')).json();
    assert.equal(s.snapshot.engine_running,true,'the tunnel toggle leaves the engine alone');
   }
  }

  // Потеря API: последний снимок приглушён и честно подписан.
  await call('Network.enable');
  await call('Network.setBlockedURLs',{urls:[panel.url+'api/status']});
  await wait(11500);
  assert.equal(await evaluate('document.body.dataset.stale'),'true','lost API must mark the snapshot stale');
  assert.equal(await evaluate('document.querySelector("[data-tg-state-title]").textContent'),'Данные API устарели',
   'stale API status is visible beside the route summary');
  assert.match(await evaluate('document.querySelector("#notice").textContent'),/Нет ответа от панели/);
  await call('Network.setBlockedURLs',{urls:[]});
  await until('document.body.dataset.stale==="false"','recovered API must clear the stale mark');
  // «Уменьшить движение»: без сцен, но всё работает.
  await call('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  await call('Page.reload');
  await until('document.querySelectorAll(".search").length===2','reduced-motion page renders');
  await evaluate('document.querySelector(".crate-lid").click()');
  assert.equal(await evaluate('document.querySelector(".crate").open'),true,'reduced motion opens the crate natively at once');
  assert.equal(await evaluate('gsap.globalTimeline.getChildren(true,true,false).filter(t=>t.isActive()).length'),0,'reduced motion runs no tweens');
  assert.equal(await evaluate('!!document.querySelector("#telegram-body .tg-flow-canvas")'),true,'reduced motion preserves the C11 route visualization');
  assert.equal(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").dataset.state'),'mixed','reduced motion preserves the active route snapshot');
  await evaluate('(()=>{window.__tgReducedMotionFrames=0;const raf=window.requestAnimationFrame;window.requestAnimationFrame=function(cb){return raf.call(window,ts=>{window.__tgReducedMotionFrames++;cb(ts)})};document.querySelector("#telegram-body .tg-flow-canvas").scrollIntoView({block:"center"})})()');
  await until('window.__tgReducedMotionFrames>0',
   'the visible Telegram route visualization continues animating when Windows requests reduced motion');
  if(process.env.D2K_TUNNEL_SHOTS){await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');await wait(200);
   const b=await evaluate('(()=>{const r=document.querySelector("#telegram-body").getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height}})()');
   const s=await call('Page.captureScreenshot',{format:'png',clip:{...b,scale:2}});fs.writeFileSync(path.join(process.env.D2K_TUNNEL_SHOTS,'9-reduced-motion-connected.png'),Buffer.from(s.data,'base64'))}
  await call('Emulation.setEmulatedMedia',{features:[]});
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
  await call('Fetch.enable',{patterns:[{url:'*',requestStage:'Request'}]});
  diagnosticsReply=diagnosticFixture('full');
  await call('Page.reload');
  await until('document.querySelector("#diagnostic-memory-chart")?.dataset.points==="121"','two-hour diagnostics history renders');
  await evaluate('document.querySelector("[data-memory-range=\\"24\\"]").click()');
  await until('document.querySelector("#diagnostic-memory-chart")?.dataset.points==="1440"','1440 compact memory samples render in the 24-hour view');
  await evaluate('document.querySelector("#diagnostics").scrollIntoView({block:"start"})');
  assert.equal(await evaluate('document.querySelector("#diagnostic-data").hidden'),false,'enabled report content is visible');
  await evaluate('document.querySelectorAll("[data-memory-series]").forEach(input=>{input.checked=true;input.dispatchEvent(new Event("change",{bubbles:true}))})');
  assert.deepEqual(await evaluate('Array.from(document.querySelectorAll("#diagnostic-memory-chart path[data-series]"),node=>node.dataset.series)'),
   ['rss','rss_anon','vm_data','anonymous','private_dirty','catalog','http','snapshot','tracked_tcp','tracked_quic','tracked_tls'],
   'all available RSS, process and subsystem metrics are plotted when selected');
  assert.equal(await evaluate('document.querySelector("#diagnostic-catalog-bytes").textContent'),'9.4 КиБ','9625 catalog bytes format consistently in the card');
  assert.equal(await evaluate('document.querySelector("[data-series-option=catalog] small").textContent.split(" · ")[0]'),
   await evaluate('document.querySelector("#diagnostic-catalog-bytes").textContent'),'catalog card and legend use the same byte value');
  assert.equal(await evaluate('document.querySelector("#diagnostic-http-bytes").textContent'),'5.4 КиБ','5529 HTTP bytes format consistently in the card');
  assert.equal(await evaluate('document.querySelector("[data-series-option=http] small").textContent.split(" · ")[0]'),
   await evaluate('document.querySelector("#diagnostic-http-bytes").textContent'),'HTTP card and legend use the same byte value');
  assert.match(await evaluate('document.querySelector("#diagnostic-history-coverage").textContent'),/Доступно 23 ч 59 мин из 24 часа/,
   'selected 24-hour range shows the duration actually retained');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/RSS вырос/,'positive RSS growth is visible as a qualified information notice');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/Часть истории вытеснена/,'overwritten diagnostic records are reported');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/Подробная карта памяти недоступна на этом устройстве/,'optional smaps data is a calm information notice');
  assert.doesNotMatch(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/errno 2/,'expected unsupported procfs capability is described instead of shown as an operational errno');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/без сопоставимого роста/,'unattributed RSS anomaly is reported without calling it a leak');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/Не удалось сохранить диагностический JSON/,'JSON write failures are visible');
  assert.match(await evaluate('document.querySelector("#diagnostic-memory-tracking-coverage").textContent'),/выделенные при включённом сборе/,'tracking coverage is separate from history duration');
  assert.match(await evaluate('document.querySelector("#diagnostic-madvise-results").textContent'),/10 \/ 1/,'madvise outcomes are visible');
  assert.equal(await evaluate('document.querySelector("#diagnostic-workers-running").textContent'),'3','active workers are shown');
  assert.equal(await evaluate('document.querySelector("#diagnostic-workers-errors").textContent'),'2 / 1','thread start and join errors are shown');
  assert.match(await evaluate('document.querySelector("#diagnostic-http-records").textContent'),/256\.0 КиБ/,'HTTP record storage shows its report-provided cap');
  assert.match(await evaluate('document.querySelector("#diagnostic-http-overflows").textContent'),/очередь — 3/,'HTTP overflow counters are shown');
  assert.match(await evaluate('document.querySelector("#diagnostic-aimd-current").textContent'),/1\/1.*память, conntrack/,'current 1/1 limiter and its causes are shown');
  assert.match(await evaluate('document.querySelector("#diagnostic-aimd-history").textContent'),/1 \/ 1.*память/,'AIMD transition history includes the 1/1 cause');
  assert.equal(await evaluate('document.querySelector("#diagnostic-download").getAttribute("href")'),'/api/diagnostics?download','the complete JSON download endpoint stays linked');
  await evaluate('document.querySelector("#diagnostic-telegram-tab").click()');
  await until('document.querySelector("#telegram-diagnostic-memory-chart")?.dataset.points==="3"','Telegram memory history renders in its tab');
  assert.equal(await evaluate('document.querySelector("#telegram-diagnostic-traffic-chart").dataset.points'),'3','Telegram throughput history uses the same time range');
  assert.equal(await evaluate('document.querySelector("#telegram-diagnostic-resource-chart").dataset.points'),'3','Telegram connection and resource history uses the same time range');
  assert.equal(await evaluate('document.querySelector("#telegram-diagnostic-data").hidden'),false,'Telegram diagnostics are independently visible');
  assert.equal(await evaluate('document.querySelector("#tg-diag-rss").textContent'),'1.5 МиБ / 2.0 МиБ','Telegram RSS and high-water mark are shown');
  assert.equal(await evaluate('document.querySelector("#tg-diag-smaps-status").textContent'),'нет в procfs','missing optional smaps data is shown as unavailable');
  assert.equal(await evaluate('document.querySelector("#tg-diag-pss-available").textContent'),'unavailable / 8.0 МиБ / 128.0 МиБ','PSS and system memory remain separate and missing PSS is explicit');
  assert.equal(await evaluate('document.querySelector("#tg-diag-smaps-details").textContent'),'unavailable / unavailable / unavailable','missing smaps components are not reported as zero');
  assert.equal(await evaluate('document.querySelector("[data-tg-memory-series=vm_swap]").parentNode.hidden'),false,'VmSwap history is available as a selectable memory series');
  assert.equal(await evaluate('document.querySelector("#tg-diag-wss").textContent'),'12 / 3 / 8','WSS totals are visible');
  assert.equal(await evaluate('document.querySelector("#tg-diag-error-delta").textContent'),'1 / 1 / 1 / 2','HTTP status and WSS error deltas remain distinguishable');
  assert.equal(await evaluate('document.querySelector("#tg-diag-latency").textContent'),'42.7 мс / 187.0 мс','application response latency percentiles are shown');
  assert.match(await evaluate('document.querySelector("#tg-diag-queues").textContent'),/клиент 512 Б \/ 4\.0 КиБ.*upstream 256 Б \/ 2\.0 КиБ/,'current queue fill is shown next to capacity');
  assert.match(await evaluate('document.querySelector("#tg-diag-stage-failures").textContent'),/connect 2.*handshake 1/,'failure counts are grouped by stage');
  assert.match(await evaluate('document.querySelector("#tg-diag-throughput").textContent'),/50 Б\/с \/ 25 Б\/с/,'last-interval throughput is shown');
  assert.match(await evaluate('document.querySelector("#tg-diag-map-status").textContent'),/last-known-good да/,'last-known-good DC map state is visible');
  assert.match(await evaluate('document.querySelector("#tg-diag-map-refresh").textContent'),/http_error.*errno 104/,'failed DC map refresh reason and errno are visible');
  assert.match(await evaluate('document.querySelector("#tg-diag-allocation-breakdown").textContent'),/прокси 2\.0 КиБ.*соединения 2\.0 КиБ.*worker pool 512 Б/,'accounted proxy and connection memory is broken down');
  assert.match(await evaluate('document.querySelector("#tg-diag-sessions").textContent'),/media.*420 мс \/ 3 с/,'media sessions show activity, first response and time since progress');
  assert.match(await evaluate('document.querySelector("#tg-diag-sessions").textContent'),/5\.0 КиБ\/с \/ 2\.5 КиБ\/с/,'per-session lifetime throughput is displayed');
  assert.equal(await evaluate('document.querySelector("#tg-diag-sessions tr").children.length'),6,'session details match all six diagnostic columns');
  assert.match(await evaluate('document.querySelector("#tg-diag-sessions").textContent'),/420 мс \/ 3 с.*direct selected.*fallback idle/,'first response, no-progress age, and both route states are shown');
  assert.match(await evaluate('document.querySelector("#tg-diag-limit-history").textContent'),/Буферы: 64\.0 КиБ → 128\.0 КиБ/,'Telegram limit changes are shown from minute samples');
  diagnosticsReply=diagnosticFixture('telegram_generation_change');await call('Page.reload');
  await until('document.querySelector("#telegram-diagnostic-memory-chart")?.dataset.points==="3"','Telegram process generation fixture renders');
  assert.equal(await evaluate('document.querySelectorAll("#telegram-diagnostic-memory-chart .diag-line-rss").length'),2,'memory lines break when a PID is reused by a new process generation');
  diagnosticsReply=diagnosticFixture('telegram_smaps_available');await call('Page.reload');
  await until('document.querySelector("#telegram-diagnostic-memory-chart")?.dataset.points==="3"','smaps history fixture renders');
  assert.equal(await evaluate('document.querySelector("[data-tg-memory-series=smaps_pss]").parentNode.hidden'),false,'PSS is charted when smaps_rollup is available');
  assert.equal(await evaluate('document.querySelector("[data-tg-memory-series=smaps_private_dirty]").parentNode.hidden'),false,'Private_Dirty is charted when smaps_rollup is available');
  assert.ok(await evaluate('document.querySelectorAll("#telegram-diagnostic-memory-chart path.diag-line-private_dirty").length>0'),'Private_Dirty history is drawn');
  assert.equal(await evaluate('document.querySelector("#tg-diag-smaps-details").textContent'),'900.0 КиБ / 640.0 КиБ / 2.0 КиБ','smaps Anonymous, Private_Dirty and Swap values are shown');
  diagnosticsReply=diagnosticFixture('telegram_unavailable');await call('Page.reload');
  await until('document.querySelector("#telegram-diagnostic-memory-chart")?.dataset.points==="3"','Telegram unavailable metric fixture renders');
  assert.match(await evaluate('document.querySelector("#tg-diag-rss").textContent'),/^unavailable \/ 2\.0 МиБ$/,'unknown memory values are labelled unavailable');
  diagnosticsReply=diagnosticFixture('telegram_socket_unavailable');await call('Page.reload');
  await until('document.querySelector("#telegram-diagnostic-memory-chart")?.dataset.points==="3"','stale Telegram snapshot renders');
  assert.match(await evaluate('document.querySelector("#telegram-diagnostic-status").textContent'),/Текущий срез недоступен.*110.*последний успешный/,'failed socket reads do not present the previous sample as current');
  diagnosticsReply=diagnosticFixture('telegram_socket_empty');await call('Page.reload');
  await until('document.querySelector("#telegram-diagnostic-status").textContent.includes("код 110")','first failed read is explained');
  assert.equal(await evaluate('document.querySelector("#telegram-diagnostic-data").hidden'),true,'empty panels are hidden before the first sample');
  diagnosticsReply=diagnosticFixture('telegram_first_sample');await call('Page.reload');
  await until('document.querySelector("#telegram-diagnostic-memory-chart circle.diag-line-rss")!==null','first RSS sample has a visible point');
  assert.equal(await evaluate('document.querySelector("#telegram-diagnostic-data").hidden'),false,'data panels appear with the first sample');
  diagnosticsReply=diagnosticFixture('units');await call('Page.reload');
  await until('document.querySelector("#diagnostic-memory-chart").dataset.points==="2"','controlled metric fixture renders');
  await evaluate('document.querySelectorAll("[data-memory-series]").forEach(input=>{input.checked=true;input.dispatchEvent(new Event("change",{bubbles:true}))})');
  const deltas=await evaluate('Object.fromEntries(Array.from(document.querySelectorAll("[data-series-option]"),label=>[label.dataset.seriesOption,label.querySelector("small")?.textContent]))');
  for(const [series,delta] of [['rss','+1.0 МиБ'],['rss_anon','+512.0 КиБ'],['vm_data','+2.0 МиБ'],
   ['tracked_tcp','+1.0 КиБ'],['tracked_quic','−2.0 КиБ'],['tracked_tls','+8.0 КиБ']])
   assert.ok(deltas[series].endsWith(delta),'independent '+series+' delta is shown, got '+deltas[series]);
  diagnosticsReply=diagnosticFixture('sample_mismatch');await call('Page.reload');
  await until('document.querySelector("#diagnostic-warnings").textContent.includes("Несовпадение объёмов в отчёте")','same-time byte mismatch is exposed');
  assert.equal(await evaluate('document.querySelector("#diagnostic-catalog-bytes").textContent'),'9.4 КиБ','card keeps the chart history value');
  assert.match(await evaluate('document.querySelector("#diagnostic-catalog-note").textContent'),/Время снимка совпадает, но объёмы расходятся/,'catalog card explains the conflicting aggregate value');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/общий снимок 10\.4 КиБ/,'mismatch includes both source values in collapsed details');
  diagnosticsReply=diagnosticFixture('time_mismatch');await call('Page.reload');
  await until('document.querySelector("#diagnostic-process-note").textContent.includes("разница")','different sample times are called out');
  assert.match(await evaluate('document.querySelector("#diagnostic-catalog-note").textContent'),/разница 1 мин/,'catalog history and counters show their offset');
  diagnosticsReply=diagnosticFixture('pid_change');await call('Page.reload');
  await until('document.querySelector("#diagnostic-memory-chart").dataset.points==="2"','PID generation fixture renders');
  await evaluate('document.querySelectorAll("[data-memory-series]").forEach(input=>{input.checked=true;input.dispatchEvent(new Event("change",{bubbles:true}))})');
  assert.doesNotMatch(await evaluate('document.querySelector("[data-series-option=rss] small").textContent'),/· [+-−]/,'RSS delta is not joined across a PID change');
  diagnosticsReply=diagnosticFixture('short');await call('Page.reload');
  await until('document.querySelector("#diagnostic-memory-chart").dataset.points==="11"','short history renders');
  await evaluate(`document.querySelector('[data-memory-range="24"]').click()`);
  assert.match(await evaluate('document.querySelector("#diagnostic-history-coverage").textContent'),/Доступно 10 мин из 24 часа/,'24-hour view reports only ten available minutes');
  for(const kind of ['legacy_history','legacy_no_fields']){
   diagnosticsReply=diagnosticFixture(kind);await call('Page.reload');
   await until('document.querySelector("#diagnostic-memory-chart").dataset.points==="2"',kind+' report renders');
   assert.equal(await evaluate('document.querySelector("#diagnostic-catalog-bytes").textContent'),'9.4 КиБ',kind+' exact matched byte value is retained');
   assert.equal(await evaluate('document.querySelector("#diagnostic-http-bytes").textContent'),'5.4 КиБ',kind+' keeps HTTP units consistent');
  }
  diagnosticsReply=diagnosticFixture('fallback');await call('Page.reload');
  await until('document.querySelector("#diagnostic-memory-chart").dataset.points==="1"','fallback memory snapshot renders');
  await evaluate('document.querySelectorAll("[data-memory-series]").forEach(input=>{input.checked=true;input.dispatchEvent(new Event("change",{bubbles:true}))})');
  const fallbackSeries=await evaluate('Array.from(document.querySelectorAll("#diagnostic-memory-chart path[data-series]"),node=>node.dataset.series)');
  assert.ok(fallbackSeries.includes('anonymous')&&fallbackSeries.includes('private_dirty'),'smaps fallback metrics render when smaps_rollup is unsupported');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/Подробная карта памяти недоступна на этом устройстве/,'unsupported rollup stays informational');
  assert.doesNotMatch(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/errno 2/,'fallback does not report the expected absent optional procfs path as an error');
  await evaluate(`document.querySelector('[data-memory-range="2"]').click()`);
  assert.equal(await evaluate('document.querySelector("#diagnostic-memory-chart").dataset.points'),'1','range selection does not synthesize unavailable fallback samples');
  for(const width of [320,390]){
   await call('Emulation.setDeviceMetricsOverride',{width,height:844,deviceScaleFactor:1,mobile:true});
   await wait(100);
   assert.equal(await evaluate('document.documentElement.scrollWidth>innerWidth'),false,'diagnostics fit the '+width+'px mobile viewport');
  }
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
  if(process.env.D2K_DIAG_SHOTS){
   await evaluate('document.querySelector("#diagnostics").scrollIntoView({block:"start"})');await wait(150);
   const b=await evaluate('(()=>{const r=document.querySelector(".diag-history").getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height}})()');
   const shot=await call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true,clip:{...b,scale:1}});
   fs.mkdirSync(process.env.D2K_DIAG_SHOTS,{recursive:true});
   fs.writeFileSync(path.join(process.env.D2K_DIAG_SHOTS,'diagnostics-desktop.png'),Buffer.from(shot.data,'base64'));
  }
  diagnosticsReply=diagnosticFixture('empty');await call('Page.reload');
  await until('document.querySelector("#diagnostic-status").textContent.includes("Ожидаем первый снимок")','empty report remains usable');
  assert.equal(await evaluate('document.querySelector("#diagnostic-data").hidden'),false,'enabled empty history keeps the panel visible');
  assert.equal(await evaluate('document.querySelector("#diagnostic-memory-empty").hidden'),false,'empty history has an explicit chart state');
  assert.equal(await evaluate('document.querySelector("#diagnostic-download").hidden'),false,'empty enabled report can still be downloaded');
  diagnosticsReply=diagnosticFixture('unavailable');await call('Page.reload');
  await until('!document.querySelector("#diagnostic-warnings").hidden','unavailable memory metadata produces a warning');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/errno 13/,'rollup errno is retained in the warning');
  assert.deepEqual(await evaluate('Array.from(document.querySelectorAll("#diagnostic-memory-chart path[data-series]"),node=>node.dataset.series)'),
   ['rss_anon'],'RssAnon remains plotted while unavailable metrics are omitted');
  diagnosticsReply=diagnosticFixture('unsupported');await call('Page.reload');
  await until('!document.querySelector("#diagnostic-warnings").hidden','OpenWrt without proc page monitoring explains unsupported smaps');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/Подробная карта памяти недоступна на этом устройстве/,'missing rollup has the requested calm title');
  assert.equal(await evaluate('document.querySelectorAll("#diagnostic-warnings .diag-notice--warning").length'),0,'ordinary procfs capability absence stays neutral');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/в 2 снимках/,'two unsupported rollup samples are counted');
  assert.doesNotMatch(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/гонкой при остановке процесса/,'unsupported means the PID exists but the kernel interface is absent');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/KERNEL_PROC_PAGE_MONITOR и CONFIG_PROC_PAGE_MONITOR=y/,'firmware option needed for optional smaps metrics is explicit');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/RSS, RssAnon, VmData и учтённые D2O объекты продолжают собираться/,'OpenWrt baseline metrics stay available without smaps');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/CONFIG_PROC_PAGE_MONITOR/,'OpenWrt guidance points to the kernel setting behind optional rollup metrics');
  assert.equal(diagnosticsReply.memory_details[0].latest.smaps_rollup_status,'unsupported','OpenWrt procfs absence is classified as unsupported in JSON');
  assert.equal(diagnosticsReply.memory_details[0].latest.smaps_rollup_errno,null,'OpenWrt procfs feature absence is not serialized as a syscall error');
  assert.doesNotMatch(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/errno 2/,'ENOENT is described as an optional kernel procfs capability, not a D2O runtime failure');
  assert.deepEqual(await evaluate('Array.from(document.querySelectorAll("#diagnostic-memory-chart path[data-series]"),node=>node.dataset.series)'),
   ['rss','rss_anon','vm_data'],'RSS, RssAnon and VmData remain charted when smaps_rollup is missing');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/без сопоставимого роста/,'RSS anomaly remains visible in the OpenWrt case');
  diagnosticsReply=diagnosticFixture('legacy');await call('Page.reload');
  await until('document.querySelector("#diagnostic-memory-chart").dataset.points==="1"','legacy report memory fields still render');
  assert.deepEqual(await evaluate('Array.from(document.querySelectorAll("#diagnostic-memory-chart path[data-series]"),node=>node.dataset.series)'),
   ['rss','rss_anon','vm_data','anonymous','private_dirty'],'legacy RssAnon and detailed smaps metrics keep their meanings');
  diagnosticsReply=diagnosticFixture('legacy_enoent');await call('Page.reload');
  await until('!document.querySelector("#diagnostic-warnings").hidden','legacy ENOENT rollup metadata is classified');
  assert.match(await evaluate('document.querySelector("#diagnostic-warnings").textContent'),/Подробная карта памяти недоступна на этом устройстве/,'legacy ENOENT is calm when the PID is present');
  assert.equal(await evaluate('document.querySelectorAll("#diagnostic-warnings .diag-notice--warning").length'),0,'optional ENOENT is not yellow');
  assert.equal(await evaluate('document.querySelector("#diagnostic-warnings details").open'),false,'technical errno details start collapsed');
  assert.doesNotMatch(await evaluate('document.querySelector("#diagnostic-warnings .diag-notice-text").textContent'),/errno 2/,'technical errno stays inside the disclosure');
  assert.deepEqual(await evaluate('Array.from(document.querySelectorAll("#diagnostic-memory-chart path[data-series]"),node=>node.dataset.series)'),
   ['rss','rss_anon','vm_data'],'legacy ENOENT keeps RSS, RssAnon and VmData while omitting unavailable smaps values');
  diagnosticsReply=diagnosticFixture('legacy_smaps_enoent');await call('Page.reload');
  await until('document.querySelector("#diagnostic-status").textContent.includes("Обновлено")','old report with missing smaps renders');
  assert.equal(await evaluate('document.querySelectorAll("#diagnostic-warnings .diag-notice--warning").length'),0,'missing optional smaps is not a warning');
  assert.deepEqual(exceptions,[]);
  console.log('Browser + C panel: byte units, independent deltas, time/PID alignment, optional smaps, 10-minute coverage, 1440 samples, layout and commands passed.');
 }finally{await panel.close()}
}
main().catch(e=>{console.error(e);process.exitCode=1}).finally(()=>{if(ws)ws.close();chrome.kill()});
