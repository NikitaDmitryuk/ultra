const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const source=fs.readFileSync(require('node:path').join(__dirname,'../internal/bot/embed/miniapp/cabinet.js'),'utf8');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function page(self,responses){
 const elements=new Map(),calls=[],copied=[],opened=[];
 function el(id){if(!elements.has(id))elements.set(id,{innerHTML:'',value:'',dataset:{},classList:{toggle(){}},querySelectorAll(){return[]},addEventListener(){},showModal(){this.open=true},close(){this.open=false}});return elements.get(id)}
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
 assert.equal(p.calls.length,1);
});
test('Vultr displays server DTO price and replica state',async()=>{
 const p=page(false,{'/api/me':{is_admin:true},'/api/members':[], '/api/cloud/operations':[{id:'op',offer:{region:{city:'Frankfurt'},plan:{id:'vc2-1c-1gb'},price:{monthly_cost:5,hourly_cost:.007}},state:'ready',phase:'ready',charged:true,instance_id:'instance'}],'/api/cloud/replicas':[{name:'Amsterdam',state:'streaming',free_bytes:10*1073741824,required_bytes:5*1073741824}]});await flush();await vm.runInContext('service()',p.context);
 assert.ok(p.el('#app').innerHTML.includes('$5/месяц'));assert.ok(!p.el('#app').innerHTML.includes('$undefined'));
 assert.ok(p.el('#app').innerHTML.includes('Копия обновляется'));assert.ok(!p.el('#app').innerHTML.includes('Добавить узел вручную'));
});
