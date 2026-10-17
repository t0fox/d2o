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
 active_connections:3,process_started_at:100,accepted_connections:77,max_connections:256,
 connections_started:77,bytes_from_clients:1200,bytes_from_upstreams:980,wss_attempts:12,
 wss_failures:2,wss_responses:5,cf_wss_responses:1,last_success_dc:2,last_success_route:1,
 last_success_latency_ms:42,last_success_age_ms:100,last_failure_dc:4,last_failure_route:3,
 last_failure_stage:4,last_failure_age_ms:9000,route_sessions_truncated:false,
 active_sessions:[
  {id:71,dc:2,is_media:false,stage:'upstream_ready',direct_state:'selected',direct_transport:'direct_wss',
   fallback_state:'idle',fallback_transport:null,selected_transport:'direct_wss',telegram_response_seen:false,events:[]},
  {id:72,dc:2,is_media:true,stage:'routing',direct_state:'failed',direct_transport:'direct_wss',
   fallback_state:'connecting',fallback_transport:'cloudflare_worker',selected_transport:null,telegram_response_seen:false,
   events:[{sequence:1,branch:'direct',transport:'direct_wss',state:'connecting'},
    {sequence:2,branch:'direct',transport:'direct_wss',state:'failed'},
    {sequence:3,branch:'fallback',transport:'cloudflare_worker',state:'connecting'}]},
  {id:73,dc:null,is_media:null,stage:'upstream_ready',direct_state:'selected',
   direct_transport:'tcp_passthrough',fallback_state:'idle',fallback_transport:null,
   selected_transport:'tcp_passthrough',telegram_response_seen:false,events:[]}
 ]},knowledge:{
 searches:[
  {target:'rutracker.org',family:4,transport:6,ip:'104.21.32.39',port:443,phase:'распознаём поведение',since:iso(40),attempts:0,probes:5,candidate:'',source:'',question:'принимает ли ответ на усечённое приветствие'},
  {target:'video.example',family:6,transport:17,ip:'2001:db8::5',port:443,phase:'проверяем готовое узнанной коробки',since:iso(200),attempts:1,probes:3,candidate:'план поставлен',source:'готовый план узнанной коробки'},
  {target:'queued.example',family:4,transport:6,ip:'192.0.2.7',port:443,phase:'ожидает безопасного слота замера',since:iso(20),attempts:0,probes:0,candidate:'',source:''}
 ],
 groups:[{suffix:'example.com',transport:6,family:4,shape:1,evidence_count:3,plan_id:'plan-a',probe_path:'/',ech_origin:'',active:true,
  evidence:['a.example.com','b.example.com','c.example.com'],exceptions:[{name:'skip.example.com'}]}],
 boxes:[{id:'box-a',created:iso(3600),updated:iso(60),signals:[{kind:'silent',human:'ответа на приветствие не было',seen:3}],
  plans:[{id:'plan-a',proto:'tls',successes:4,enabled:true,human:'',text:'d2k-plan 1 1\nproto tcp tls\nsplit payload_start +1\norder reverse\n'}],
  bindings:[
   {target:'<img src=x onerror=alert(1)>',family:4,transport:6,shape:1,kind:'name',level:2,level_name:'сервер ответил',successes:1,confirmed:iso(90),enabled:true,recheck:false},
   {target:'a.example.com',family:4,transport:6,shape:1,kind:'name',level:3,level_name:'обмен прошёл',successes:2,confirmed:iso(120),enabled:true,recheck:false},
   {target:'a.example.com',family:6,transport:6,shape:1,kind:'name',level:3,level_name:'обмен прошёл',successes:1,confirmed:iso(130),enabled:true,recheck:true},
   {target:'skip.example.com',family:4,transport:6,shape:1,kind:'name',level:3,level_name:'обмен прошёл',successes:1,confirmed:iso(140),enabled:true,recheck:false}
  ]}],
 measurements:{active:1,limit:4,queued:0,cores:2,free_pct:80},targets:4,confirms:7,probes_used:30,client_unfit:0}};
let ws;
async function main(){
 let port;
 for(let i=0;i<100;i++){try{port=fs.readFileSync(path.join(profile,'DevToolsActivePort'),'utf8').split('\n')[0];break}catch{}await new Promise(r=>setTimeout(r,100))}
 if(!port)throw Error('Headless browser unavailable: '+chromeError);
 const tab=await(await fetch('http://127.0.0.1:'+port+'/json/new?about:blank',{method:'PUT'})).json();
 ws=new WebSocket(tab.webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j});
 let id=0;const pending=new Map(),exceptions=[],dialogs=[];
 ws.onmessage=e=>{const x=JSON.parse(e.data);if(x.id){const p=pending.get(x.id);pending.delete(x.id);x.error?p.reject(x.error):p.resolve(x.result)}
 else if(x.method==='Page.javascriptDialogOpening'){dialogs.push(x.params.message);call('Page.handleJavaScriptDialog',{accept:true})}
 else if(x.method==='Runtime.exceptionThrown')exceptions.push(x.params.exceptionDetails)};
 const call=(method,params={})=>new Promise((resolve,reject)=>{pending.set(++id,{resolve,reject});ws.send(JSON.stringify({id,method,params}))});
 const evaluate=async(expression)=>{try{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value}catch(e){throw Error('Runtime.evaluate failed for '+expression+': '+(e?.message||JSON.stringify(e)))}};
 const wait=ms=>new Promise(r=>setTimeout(r,ms));
 const until=async(expr,msg)=>{for(let i=0;i<160;i++){if(await evaluate(expr))return;await wait(50)}throw Error(msg)};
 await call('Page.enable');await call('Runtime.enable');
 const out=process.env.D2K_CAPTURE_DIR;
 const panel=await require('./browser-c-fixture.cjs')(fixture);
 try{
  await call('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
  await call('Page.navigate',{url:panel.url});
  await until('document.querySelectorAll(".search").length===2','C API must populate the live searches');
  await evaluate('document.fonts.ready');
  assert.equal(await evaluate('document.fonts.check("700 24px Onest")'),true,'C CSP must load the bundled text face');
  async function checkLayout(){
  // Раскладка на ширинах содержимого.
  for(const [name,width,height] of [['narrow',320,740],['phone',390,844],['compact-boundary',640,1020],['overlap-regression',649,1020],['small-tablet',650,1020],['chrome-report',678,1020],['mid-tablet',700,1020],['tablet',768,1024],['tablet-boundary',820,1020],['full-label-boundary',821,1020],['status-regression',854,1020],['large-tablet',971,1020],['nav-boundary',1080,1020],['laptop',1280,800],['wide',1920,1080]]){
   if(process.env.D2K_BASELINE_OVERLAP==='1'&&width!==649)continue;
   await call('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<600});
   await evaluate('scrollTo(0,0)');await wait(120);
   const state=await evaluate(`(()=>{
    const buttons=[...document.querySelectorAll("#engine-actions [data-control]")];
    const brand=[...document.querySelectorAll(".mast-id .mark, .mast-id .wordmark")].map(x=>x.getBoundingClientRect());
    const range=document.createRange();range.selectNodeContents(document.querySelector(".mast-state-text"));
    const protectedRects=brand.concat([...range.getClientRects()]);
    const intersects=(a,b)=>a.left<b.right&&a.right>b.left&&a.top<b.bottom&&a.bottom>b.top;
    return {overflow:document.documentElement.scrollWidth>innerWidth,
     telegramCanvasHeight:document.querySelector("#telegram-body .tg-flow-canvas")?.getBoundingClientRect().height||0,
     bad:buttons.filter(x=>{const r=x.getBoundingClientRect();return r.left<0||r.right>innerWidth||r.top<0||r.height<44||r.width<44}).map(x=>x.dataset.control),
     overlaps:buttons.filter((x,i)=>protectedRects.some(r=>intersects(x.getBoundingClientRect(),r))||buttons.slice(i+1).some(y=>intersects(x.getBoundingClientRect(),y.getBoundingClientRect()))).map(x=>x.dataset.control)};
   })()`);
   console.log('layout',name,JSON.stringify(state));
   if(state.overflow)console.log('overflow by',await evaluate('[...document.body.querySelectorAll("*")].filter(x=>{const r=x.getBoundingClientRect();return r.width&&r.right>innerWidth+1}).map(x=>x.tagName+"."+(x.getAttribute("class")||"")+" right="+Math.round(x.getBoundingClientRect().right)+" style="+(x.getAttribute("style")||"")).slice(0,8)'));
   if(out){const s=await call('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(out,'panel-'+name+'.png'),Buffer.from(s.data,'base64'))}
   assert.equal(state.overflow,false,name+' horizontal overflow');
   if(width<=640)assert(state.telegramCanvasHeight>=148&&state.telegramCanvasHeight<=176,name+' Telegram diagram fits the phone layout');
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
  assert.equal(await evaluate('document.querySelector("#telegram-body").dataset.state'),'connected');
  assert.equal(await evaluate('!!document.querySelector("#telegram-body .tg-flow-canvas")'),true,'C11 route canvas is present');

  // Telegram: маршруты, DC, media и состояния совпадают со снимком C11.
  await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');
  const shots=process.env.D2K_TUNNEL_SHOTS;
  if(shots)fs.mkdirSync(shots,{recursive:true});
  const tunnelShot=async name=>{if(!shots)return;
   const b=await evaluate('(()=>{const r=document.querySelector("#telegram-body").getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height}})()');
   const s=await call('Page.captureScreenshot',{format:'png',clip:{...b,scale:2}});fs.writeFileSync(path.join(shots,name+'.png'),Buffer.from(s.data,'base64'))};
  const tunnelState=async st=>{panel.telegram(st);await until('document.querySelector("#telegram-body").dataset.state==="'+st+'"','tunnel must reach '+st)};
  await evaluate('(()=>{window.tgFlowCanvas=document.querySelector("#telegram-body .tg-flow-canvas");return true})()');
  assert.equal(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").dataset.state'),'mixed','C11 sessions show active and connecting route states');
  assert.match(await evaluate('document.querySelector("#tg-flow-caption").textContent'),/DC2 · media 1/);
  assert.equal(await evaluate('document.querySelector("[data-tg-session-count]").textContent'),'3');
  assert.equal(await evaluate('document.querySelectorAll(".tg-flow-session").length'),3,'the compact session block follows active C11 sessions');
  assert.match(await evaluate('document.querySelector("[data-tg-active-sessions]").textContent'),/DC2 · основная[\s\S]*Прямой WSS[\s\S]*ответ Telegram/);
  assert.match(await evaluate('document.querySelector("[data-tg-active-sessions]").textContent'),/DC2 · media[\s\S]*Cloudflare Worker/);
  assert.equal(await evaluate('document.querySelector("[data-tg-accepted-count]").textContent'),'77');
  assert.equal(await evaluate('document.querySelector("[data-tg-confirmed-count]").textContent'),'5');
  assert.match(await evaluate('document.querySelector("[data-tg-last-success]").textContent'),/DC2 · прямой WSS/);
  assert.doesNotMatch(await evaluate('document.querySelector("[data-tg-active-sessions]").textContent'),/sequence|first_binary_response|fallback_state/);
  assert.match(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Клиент → d2o.*Ответ Telegram не подтверждён/);
  assert.doesNotMatch(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Прокси Cloudflare|Резервный TCP/,
    'unused routes are omitted from the diagram');
  assert.doesNotMatch(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/d2ktg C11/);
  assert.match(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Прямой TCP passthrough/);
  assert.equal(await evaluate('window.tgFlowCanvas===document.querySelector("#telegram-body .tg-flow-canvas")'),true,'route canvas is mounted once');
  await tunnelShot('1-connected');

  // Подтверждённый ответ идёт от Telegram DC обратно к клиенту.
  panel.telegramStats({...fixture.telegramStats,active_connections:0,active_sessions:[]});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("#telegram-body .tg-flow-canvas").dataset.state==="idle"','empty C11 snapshot clears active route state');
  await wait(350);
  const sessionBeforeResponse={...fixture.telegramStats.active_sessions[0],telegram_response_seen:false,events:[]};
  panel.telegramStats({...fixture.telegramStats,active_connections:1,active_sessions:[sessionBeforeResponse]});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("[data-tg-session-count]").textContent==="1"','C11 reports a new session before its first response');
  await until('document.querySelector("#telegram-body .tg-flow-canvas").dataset.state==="active"','selected route is active before response confirmation');
  await evaluate('(()=>{const canvas=document.querySelector("#telegram-body .tg-flow-canvas");const proto=CanvasRenderingContext2D.prototype;const arc=proto.arc;window.__tgResponseXs=[];window.__tgOriginalArc=arc;proto.arc=function(x,y,r,...args){if(this.canvas===canvas&&this.globalCompositeOperation==="lighter"&&r>=2.4&&r<=2.6)window.__tgResponseXs.push(x);return arc.call(this,x,y,r,...args)};return true})()');
  const confirmedSession={...sessionBeforeResponse,telegram_response_seen:true,
   events:[{sequence:1,branch:'direct',transport:'direct_wss',state:'first_binary_response'}]};
  panel.telegramStats({...fixture.telegramStats,active_connections:1,active_sessions:[confirmedSession]});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector(".tg-flow-session").textContent.includes("Ответ Telegram подтверждён")&&window.__tgResponseXs.length>3','confirmed C11 response is animated after observation');
  await wait(350);
  const responseMovement=await evaluate('({first:window.__tgResponseXs[0],last:window.__tgResponseXs.at(-1),count:window.__tgResponseXs.length})');
  assert.ok(responseMovement.count>3,'confirmed response is animated');
  assert.ok(responseMovement.first>responseMovement.last+20,'подтверждённый ответ движется от DC к клиенту');
  await evaluate('CanvasRenderingContext2D.prototype.arc=window.__tgOriginalArc;delete window.__tgOriginalArc');

  // Свежий отказ всех WSS-маршрутов не должен выглядеть как активное подключение из-за старого ответа.
  await evaluate('(()=>{const canvas=document.querySelector("#telegram-body .tg-flow-canvas");const proto=CanvasRenderingContext2D.prototype;const moveTo=proto.moveTo;window.__tgIncomingPathDraws=0;window.__tgOriginalMoveTo=moveTo;proto.moveTo=function(x,y){if(this.canvas===canvas&&this.globalCompositeOperation==="source-over"&&x===60&&y===170)window.__tgIncomingPathDraws++;return moveTo.call(this,x,y)};return true})()');
  panel.telegram('local');
  panel.telegramStats({...fixture.telegramStats,active_connections:0,active_sessions:[],
   last_failure_age_ms:100,last_success_age_ms:10000});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("#telegram-body").dataset.state==="unavailable"','new WSS failure must replace stale connected state');
  await evaluate('window.__tgIncomingPathDraws=0');
  await wait(50);
  assert.equal(await evaluate('window.__tgIncomingPathDraws'),0,'при нуле активных соединений схема не рисует линию клиент → d2o');
  await evaluate('CanvasRenderingContext2D.prototype.moveTo=window.__tgOriginalMoveTo;delete window.__tgOriginalMoveTo');
  assert.equal(await evaluate('document.querySelector(".tunnel-word").textContent'),'Маршрут недоступен');
  assert.match(await evaluate('document.querySelector(".tunnel-note").textContent'),/Последняя попытка Telegram завершилась ошибкой/);
  assert.match(await evaluate('document.querySelector("#tg-flow-caption").textContent'),/Последняя ошибка: WebSocket · DC4 · Прокси Cloudflare/);
  assert.match(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Прокси Cloudflare — отказ: 1/);
  assert.doesNotMatch(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Прямой WSS|Cloudflare Worker|Резервный TCP/,
    'failure view names only the route that actually failed');
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
  await tunnelShot('2-stopped');
  assert.equal(await evaluate('document.querySelectorAll(".tg-flow-session").length'),0,'stopped C11 exposes no active sessions');
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
  assert.equal(await evaluate('document.querySelectorAll(".ftag-wrap").length'),1,'family is drawn as a tag');
  await evaluate('document.querySelector(".ftag-box").click()');
  await until('document.querySelector(".crate").open&&!gsap.isTweening(window)','family tag link opens its box');
  await evaluate('document.querySelector(".crate-lid").click()');
  await until('!document.querySelector(".crate").open','box closes again');
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
    await until('/остановлен/.test(document.querySelector("#now-title").textContent)','stopped engine must be stated');
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
  if(process.env.D2K_TUNNEL_SHOTS){await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');await wait(200);
   const b=await evaluate('(()=>{const r=document.querySelector("#telegram-body").getBoundingClientRect();return {x:r.x+scrollX,y:r.y+scrollY,width:r.width,height:r.height}})()');
   const s=await call('Page.captureScreenshot',{format:'png',clip:{...b,scale:2}});fs.writeFileSync(path.join(process.env.D2K_TUNNEL_SHOTS,'9-reduced-motion-connected.png'),Buffer.from(s.data,'base64'))}
  await call('Emulation.setEmulatedMedia',{features:[]});
  assert.deepEqual(exceptions,[]);
  console.log('Browser + C panel: rendering, honesty, polling, layout and all six commands passed.');
 }finally{await panel.close()}
}
main().catch(e=>{console.error(e);process.exitCode=1}).finally(()=>{if(ws)ws.close();chrome.kill()});
