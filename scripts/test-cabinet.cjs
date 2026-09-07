const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const source=fs.readFileSync(require('node:path').join(__dirname,'../internal/bot/embed/miniapp/cabinet.js'),'utf8');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function page(self,responses){
 const elements=new Map(),calls=[],copied=[],opened=[];
 function el(id){if(!elements.has(id))elements.set(id,{insertAdjacentHTML(position,html){this.innerHTML+=html},innerHTML:'',value:'',dataset:{},classList:{toggle(){}},querySelectorAll(){return[]},addEventListener(){},showModal(){this.open=true},close(){this.open=false}});return elements.get(id)}
 const context=vm.createContext({URL,Date,Number,String,Error,Promise,JSON,
  location:{pathname:self?'/member':'/',hash:'',replace(){},reload(){}},
  window:{Telegram:{WebApp:{initData:'signed-test-session',ready(){},expand(){},openLink(url){opened.push(url)}}},addEventListener(){},open(){throw new Error('unexpected fallback')}},
  document:{querySelector:el,getElementById:id=>el('#'+id),querySelectorAll(){return[]}},
  navigator:{clipboard:{async writeText(text){copied.push(text)}}},
  setTimeout(){return 1},clearTimeout(){},
  fetch:async(path,options)=>{calls.push({path,options});if(!(path in responses))throw new Error('unexpected request '+path);return {ok:true,status:200,json:async()=>responses[path]}},
 });vm.runInContext(source,context);return {context,el,calls,copied,opened};
}
test('personal cabinet reuses subscription and opens HTTPS import without admin APIs',async()=>{
 const p=page(true,{'/api/self':{registered:true,is_admin:true,member:{uuid:'owner',active:true,pending:false}},'/api/self/exits':{exits:[],profiles:[]},'/api/self/subscription':{url:'https://vpn.example/sub/test',import_url:'https://vpn.example/happ#test'}});
 await flush();await p.el('#copy-sub').onclick();await p.el('#copy-sub').onclick();await p.el('#connect').onclick();
 assert.equal(p.calls.filter(c=>c.path==='/api/self/subscription').length,1);
 assert.deepEqual(p.copied,['https://vpn.example/sub/test','https://vpn.example/sub/test']);
 assert.deepEqual(p.opened,['https://vpn.example/happ#test']);
 assert.equal(p.el('#switch').hidden,false);
 assert.ok(p.calls.every(c=>c.path.startsWith('/api/self')));
 assert.ok(p.calls.every(c=>c.options.cache==='no-store'));
});
test('disabled access cannot issue a subscription',async()=>{
 const p=page(true,{'/api/self':{registered:true,is_admin:false,member:{uuid:'owner',active:false,pending:false}}});await flush();
 assert.ok(p.el('#app').innerHTML.includes('Доступ приостановлен'));
 assert.ok(!p.el('#app').innerHTML.includes('id="connect"'));
 assert.ok(p.calls.every(c=>['/api/self','/api/self/traffic'].includes(c.path)));
});
test('Vultr displays server DTO price and replica state',async()=>{
 const p=page(false,{'/api/me':{is_admin:true},'/api/members':[], '/api/cloud/operations':[{id:'op',offer:{region:{city:'Frankfurt'},plan:{id:'vc2-1c-1gb'},price:{monthly_cost:5,hourly_cost:.007}},state:'ready',phase:'ready',charged:true,instance_id:'instance'}],'/api/cloud/replicas':[{name:'Amsterdam',state:'streaming',free_bytes:10*1073741824,required_bytes:5*1073741824}]});await flush();await vm.runInContext('service()',p.context);
 assert.ok(p.el('#app').innerHTML.includes('$5/месяц'));assert.ok(!p.el('#app').innerHTML.includes('$undefined'));
 assert.ok(p.el('#app').innerHTML.includes('Копия обновляется'));assert.ok(!p.el('#app').innerHTML.includes('Добавить узел вручную'));
});

test('traffic activity is separate from permission and does not imply online',async()=>{
 const p=page(false,{'/api/me':{is_admin:true},'/api/members':[]});await flush();
 const now=Date.now();p.context.recent={active:true,pending:false,last_traffic_at:new Date(now-30000).toISOString()};
 assert.equal(vm.runInContext('usage(recent)',p.context),'Трафик за последние 2 мин');
 assert.ok(vm.runInContext('status(recent)',p.context).includes('Доступ разрешён'));
 assert.equal(vm.runInContext('usage({active:true,last_traffic_at:null})',p.context),'Трафик ещё не зафиксирован');
 p.context.old={active:true,last_traffic_at:new Date(now-3*86400000).toISOString()};
 assert.equal(vm.runInContext('usage(old)',p.context),'Без трафика 3 дн');
 assert.ok(vm.runInContext('status({active:false,pending:false})',p.context).includes('Доступ отозван'));
 assert.ok(vm.runInContext('status({active:false,pending:true})',p.context).includes('Отзываем доступ'));
 assert.ok(!vm.runInContext('usage({...recent,active:false})',p.context).includes('последние 2 мин'));
});

test('personal statistics include all devices and survive disabled access',async()=>{
 const traffic={month:'2026-09',uplink_bytes:10,downlink_bytes:20,routes:[{tag:'ams',name:'Амстердам',uplink_bytes:10,downlink_bytes:20}],days:[],day_routes:[{tag:'ams',bucket:'2026-09-08',uplink_bytes:10,downlink_bytes:20}]};
 const p=page(true,{'/api/self':{registered:true,is_admin:false,member:{uuid:'owner',active:false,pending:false,last_traffic_at:null}},'/api/self/traffic':traffic});await flush();
 assert.ok(p.el('#self-traffic').innerHTML.includes('Амстердам'));
 assert.ok(p.el('#self-traffic').innerHTML.includes('30 Б'));
 assert.ok(p.el('#app').innerHTML.includes('Трафик ещё не зафиксирован'));
 assert.ok(p.calls.every(c=>c.path.startsWith('/api/self')));
});
test('statistics failure does not replace personal cabinet or hide connect controls',async()=>{
 const p=page(true,{'/api/self':{registered:true,is_admin:false,member:{uuid:'owner',active:true,pending:false}},'/api/self/exits':{exits:[],profiles:[]}});await flush();
 assert.ok(p.el('#app').innerHTML.includes('id="connect"'));
 assert.ok(p.el('#self-traffic').innerHTML.includes('Статистика временно недоступна'));
 assert.ok(!p.el('#app').innerHTML.includes('Кабинет недоступен'));
});
test('creation errors remain visible inside the confirmation dialog',async()=>{
 const p=page(false,{'/api/me':{is_admin:true},'/api/members':[]});await flush();
 vm.runInContext(`modal('<button id="buy">Подтвердить</button>');button('buy',async()=>{throw new Error('IP bridge не разрешён в Vultr')})`,p.context);
 await p.el('#buy').onclick();
 assert.equal(p.el('#dialog-error').hidden,false);
 assert.equal(p.el('#dialog-error').textContent,'IP bridge не разрешён в Vultr');
 assert.equal(p.el('#dialog').open,true);
 assert.equal(p.el('#buy').disabled,false);
});

test('person charts select period and route without historical unattributed totals',async()=>{
 const p=page(false,{'/api/me':{is_admin:true},'/api/members':[]});await flush();
 p.context.chart={month:'2026-09',today:'2026-09-08',routes:[{tag:'direct',name:'Yandex Cloud'},{tag:'ams',name:'Амстердам'},{tag:'unknown',name:'Старый трафик'}],day_routes:[{bucket:'2026-09-08',tag:'ams',uplink_bytes:10,downlink_bytes:20},{bucket:'2026-09-08',tag:'unknown',downlink_bytes:999}],hours:[{bucket:'2026-09-08 12:00',tag:'direct',downlink_bytes:4}]};
 assert.equal(vm.runInContext('personTrafficData(chart,"month").selected.length',p.context),1);
 assert.equal(vm.runInContext('personTrafficData(chart,"day").buckets.length',p.context),24);
 assert.equal(vm.runInContext('personTrafficData(chart,"month").buckets.length',p.context),30);
 assert.equal(vm.runInContext('personTrafficData(chart,"day","ams").selected.length',p.context),0);
 vm.runInContext('renderTrafficChart(document.querySelector("#person-traffic"),chart)',p.context);
 const html=p.el('#person-traffic').innerHTML;
 assert.ok(html.includes('30 Б'));assert.ok(html.includes('Потребление по дням'));assert.ok(!html.includes('Старый трафик'));assert.ok(!html.includes('999'));
});

test('invitations identify recipient and group with links',async()=>{
 const p=page(false,{'/api/me':{is_admin:true},'/api/members':[], '/api/enrollment/group':{chat_id:-100123,title:'Друзья',enabled:true,group_url:'https://t.me/+test'},'/api/enrollment/invites':[{id:1,recipient:123,recipient_name:'Анна <Test>',expires_at:'2099-01-01'}]});await flush();await vm.runInContext('invites()',p.context);
 const html=p.el('#app').innerHTML;assert.ok(html.includes('Анна &lt;Test&gt;'));assert.ok(html.includes('tg://user?id=123'));assert.ok(html.includes('Открыть группу'));assert.ok(html.includes('Друзья'));
});
test('account balance stays independent of server operations',async()=>{
 const p=page(false,{'/api/me':{is_admin:true},'/api/members':[], '/api/cloud/account':{balance:12.5,pending_charges:1.25,observed_at:'2026-09-08T00:00:00Z'}});await flush();await vm.runInContext('loadCloudAccount()',p.context);
 assert.ok(p.el('#cloud-account').innerHTML.includes('12,50'));assert.ok(p.el('#cloud-account').innerHTML.includes('1,25'));
});
