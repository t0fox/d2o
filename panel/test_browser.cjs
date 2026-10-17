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
 active_connections:4,process_started_at:100,accepted_connections:77,max_connections:256,
 connections_started:77,bytes_from_clients:1200,bytes_from_upstreams:980,wss_attempts:12,
 wss_failures:2,wss_responses:5,cf_wss_responses:1,last_success_dc:2,last_success_route:1,
 last_success_latency_ms:42,last_success_age_ms:100,last_failure_dc:4,last_failure_route:3,
 last_failure_stage:4,last_failure_age_ms:9000,route_sessions_truncated:false,
 route_cooldown_ms:30000,route_cooldowns:[{dc:4,is_media:true,transport:'direct_wss',remaining_ms:28750,failure_stage:3}],
 client_response_latency_samples:5,client_response_latency_p50_us:42700,client_response_latency_p95_us:187000,
 active_sessions:[
  {id:71,dc:2,is_media:false,stage:'upstream_ready',direct_state:'selected',direct_transport:'direct_wss',
   fallback_state:'idle',fallback_transport:null,selected_transport:'direct_wss',telegram_response_seen:false,
   bytes_from_clients:640,bytes_from_upstreams:0,events:[]},
  {id:72,dc:4,is_media:true,stage:'routing',direct_state:'failed',direct_transport:'direct_wss',
   fallback_state:'connecting',fallback_transport:'cloudflare_worker',selected_transport:null,telegram_response_seen:false,
   bytes_from_clients:0,bytes_from_upstreams:0,
   events:[{sequence:1,age_ms:390,branch:'direct',transport:'direct_wss',state:'connecting'},
    {sequence:2,age_ms:120,failure_stage:3,branch:'direct',transport:'direct_wss',state:'failed'},
    {sequence:3,age_ms:80,branch:'fallback',transport:'cloudflare_worker',state:'connecting'}]},
  {id:73,dc:203,is_media:true,stage:'first_wss_binary_response',direct_state:'selected',
   direct_transport:'cloudflare_proxy',fallback_state:'idle',fallback_transport:null,
   selected_transport:'cloudflare_proxy',telegram_response_seen:true,
   bytes_from_clients:900,bytes_from_upstreams:760,
   events:[{sequence:1,age_ms:220,branch:'direct',transport:'cloudflare_proxy',state:'selected'},
    {sequence:2,age_ms:40,branch:'direct',transport:'cloudflare_proxy',state:'first_binary_response'}]},
  {id:74,dc:null,is_media:null,stage:'upstream_ready',direct_state:'selected',
   direct_transport:'tcp_passthrough',fallback_state:'idle',fallback_transport:null,
   selected_transport:'tcp_passthrough',telegram_response_seen:false,
   bytes_from_clients:0,bytes_from_upstreams:0,events:[]}
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
 await call('Page.addScriptToEvaluateOnNewDocument',{source:`(()=>{
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
  await evaluate('document.fonts.ready');
  assert.equal(await evaluate('document.fonts.check("700 24px Onest")'),true,'C CSP must load the bundled text face');
  try {
   await until('document.querySelector("#telegram-body .tg-flow-canvas")','C11 route canvas mounts from live stats');
  } catch(error) {
   console.error('Browser exceptions during Telegram startup:',JSON.stringify(exceptions));
   throw error;
  }
  assert.equal(await evaluate('document.querySelectorAll("[data-tg-visual-mode]").length'),0,
   'prototype demonstration controls are not exposed in the live panel');
  assert.equal(await evaluate('document.querySelectorAll(".tg-flow-block").length'),0,
   'the prototype is shown without extra technical panels');
  assert.equal(await evaluate('document.querySelectorAll(".tg-flow-legend").length'),0,
   'пользовательские пояснения не заменяются техническими инструкциями');
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
     telegramCanvas:(()=>{const r=document.querySelector("#telegram-body .tg-flow-canvas")?.getBoundingClientRect();return r?{width:r.width,height:r.height,ratio:r.width/r.height}:null})(),
     bad:buttons.filter(x=>{const r=x.getBoundingClientRect();return r.left<0||r.right>innerWidth||r.top<0||r.height<44||r.width<44}).map(x=>x.dataset.control),
     overlaps:buttons.filter((x,i)=>protectedRects.some(r=>intersects(x.getBoundingClientRect(),r))||buttons.slice(i+1).some(y=>intersects(x.getBoundingClientRect(),y.getBoundingClientRect()))).map(x=>x.dataset.control)};
   })()`);
   console.log('layout',name,JSON.stringify(state));
   if(state.overflow)console.log('overflow by',await evaluate('[...document.body.querySelectorAll("*")].filter(x=>{const r=x.getBoundingClientRect();return r.width&&r.right>innerWidth+1}).map(x=>x.tagName+"."+(x.getAttribute("class")||"")+" right="+Math.round(x.getBoundingClientRect().right)+" style="+(x.getAttribute("style")||"")).slice(0,8)'));
   if(out){const s=await call('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(out,'panel-'+name+'.png'),Buffer.from(s.data,'base64'))}
   assert.equal(state.overflow,false,name+' horizontal overflow');
   const sourceRatio=state.telegramCanvas&&state.telegramCanvas.width<420?420/900:900/420;
   assert(state.telegramCanvas&&Math.abs(state.telegramCanvas.ratio-sourceRatio)<0.02,
    name+' Telegram diagram keeps the undistorted mobile or desktop composition');
   if(width===390){
    await evaluate('document.querySelector("#telegram").scrollIntoView({block:"center"})');
    await wait(100);
    await evaluate(`(()=>{const p=CanvasRenderingContext2D.prototype,draw=p.fillText;window.__tgMobileRouteLabels=[];window.__tgMobileOriginalFillText=draw;p.fillText=function(value,...args){if(this.canvas?.classList.contains("tg-flow-canvas")&&/^(Прямой WSS|активен · 1)$/.test(String(value))){const t=this.getTransform();window.__tgMobileRouteLabels.push({text:String(value),y:t.f})}return draw.call(this,value,...args)}})()`);
    await wait(100);
    const labels=await evaluate('(()=>{const a=window.__tgMobileRouteLabels||[],i=a.findLastIndex(x=>x.text==="Прямой WSS");return {title:a[i],state:a[i+1]}})()');
    await evaluate('CanvasRenderingContext2D.prototype.fillText=window.__tgMobileOriginalFillText;delete window.__tgMobileOriginalFillText');
    assert(labels.title&&labels.state&&Math.abs(labels.title.y-labels.state.y)>=10,
     'название мобильного маршрута и его состояние стоят в разных строках');
   }
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
  await until('document.querySelector("#telegram-body").dataset.state==="connected"','C11 connected status renders in Telegram panel');
  assert.equal(await evaluate('document.querySelector("#telegram-body").dataset.state'),'connected');
  assert.equal(await evaluate('!!document.querySelector("#telegram-body .tg-flow-canvas")'),true,'C11 route canvas is present');

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
  assert.equal(await evaluate('document.querySelectorAll(".tg-flow-metric").length'),6,
    'the six prototype metrics are preserved without extra session cards');
  assert.equal(await evaluate('document.querySelector("[data-tg-accepted-count]").textContent'),'77');
  assert.equal(await evaluate('document.querySelector("[data-tg-confirmed-count]").textContent'),'5');
  assert.equal(await evaluate('document.querySelector("[data-tg-active-count]").textContent'),'4');
  assert.equal(await evaluate('document.querySelector("[data-tg-latency]").textContent'),'43 / 187 мс',
    'C11 microseconds are shown as milliseconds');
  assert.equal(await evaluate('document.querySelector("[data-tg-wss]").textContent'),'2 / 12');
  assert.equal(await evaluate('document.querySelector("[data-tg-traffic]").textContent'),'1,2 КБ / 980 Б');
  assert.match(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Клиент → d2o.*Ответ Telegram подтверждён/);
  assert.match(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/отказ на воротах TLS.*пауза 1 маршрута/,
    'failure gate and live route cooldown are announced from C11 statistics');
  assert.doesNotMatch(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Резервный TCP/,
    'unused routes are omitted from the diagram');
  assert.doesNotMatch(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/d2ktg C11/);
  assert.match(await evaluate('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label")'),/Прямой TCP passthrough/);
  assert.equal(await evaluate('window.tgFlowCanvas===document.querySelector("#telegram-body .tg-flow-canvas")'),true,'route canvas is mounted once');
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
  await evaluate('(()=>{const canvas=document.querySelector("#telegram-body .tg-flow-canvas");const proto=CanvasRenderingContext2D.prototype;const arc=proto.arc,lineTo=proto.lineTo,stroke=proto.stroke,beginPath=proto.beginPath,raf=window.requestAnimationFrame;window.__tgResponseXs=[];window.__tgLighterArcs=0;window.__tgAnimationFrames=0;window.__tgEcgSamples=0;window.__tgUnconfirmedGreenTrafficStrokes=0;window.__tgGreenDirectRouteStrokes=0;window.__tgOriginalArc=arc;window.__tgOriginalLineTo=lineTo;window.__tgOriginalStroke=stroke;window.__tgOriginalBeginPath=beginPath;window.requestAnimationFrame=function(cb){return raf.call(window,ts=>{window.__tgAnimationFrames++;cb(ts)})};proto.arc=function(x,y,r,...args){if(this.canvas===canvas&&this.globalCompositeOperation==="lighter"){window.__tgLighterArcs++;if(r>=1.8&&r<=2.2)window.__tgResponseXs.push(x)}return arc.call(this,x,y,r,...args)};proto.beginPath=function(...args){if(this.canvas===canvas)this.__tgDirectLanePath=false;return beginPath.apply(this,args)};proto.lineTo=function(x,y,...args){if(this.canvas===canvas&&Math.abs(y-62)<0.01)this.__tgDirectLanePath=true;if(this.canvas===canvas&&this.globalCompositeOperation==="source-over"&&x>=100&&x<=266&&Math.abs(y-210)>0.1)window.__tgEcgSamples++;return lineTo.call(this,x,y,...args)};proto.stroke=function(...args){if(this.canvas===canvas){const green=this.strokeStyle.includes("143, 220, 178");if(green&&this.getLineDash().length&&this.lineDashOffset!==0)window.__tgUnconfirmedGreenTrafficStrokes++;if(this.__tgDirectLanePath&&green)window.__tgGreenDirectRouteStrokes++}return stroke.apply(this,args)};return true})()');
  await wait(120);
  assert.equal(await evaluate('window.__tgResponseXs.length'),0,'upstream_ready does not invent a Telegram response pulse');
  assert.equal(await evaluate('window.__tgUnconfirmedGreenTrafficStrokes'),0,
    'неподтверждённый upstream не рисуется движущимися зелёными пакетами');
  assert.equal(await evaluate('window.__tgGreenDirectRouteStrokes'),0,
    'маршрут остаётся оранжевым до подтверждённого ответа Telegram');
  assert.equal(await evaluate('window.__tgEcgSamples'),0,'the client ECG stays quiet before a confirmed MTProto response');
  await evaluate('window.__tgResponseStartedAt=performance.now()');
  const confirmedSession={...sessionBeforeResponse,telegram_response_seen:true,
   events:[{sequence:1,branch:'direct',transport:'direct_wss',state:'first_binary_response'}]};
  panel.telegramStats({...fixture.telegramStats,active_connections:1,active_sessions:[confirmedSession]});
  await evaluate('document.dispatchEvent(new Event("visibilitychange"))');
  await until('document.querySelector("#telegram-body .tg-flow-canvas").getAttribute("aria-label").includes("Ответ Telegram подтверждён")','confirmed response reaches the live scene accessibility state');
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
  assert.equal(await evaluate('document.querySelector("[data-tg-state-title]").textContent'),'Локальный прокси');
  assert.equal(await evaluate('document.querySelector("[data-tg-state-lamp]").dataset.tone'),'bad');
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
