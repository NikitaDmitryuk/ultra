'use strict';
// This preview has no backend transport: every action stays in page memory.
(()=>{
const now=new Date().toISOString();
const people=[{uuid:'demo-1',telegram_id:100001,name:'Алексей',active:true,pending:false,source:'group',enrolled_at:now},{uuid:'demo-2',telegram_id:100002,name:'Мария',active:true,pending:true,source:'invite',enrolled_at:now},{uuid:'demo-3',telegram_id:100003,name:'Дмитрий',active:false,pending:false,source:'invite',enrolled_at:now}];
let group={chat_id:-100123456,title:'Друзья Ultra',enabled:true,url:'https://example.invalid/demo-group'};
const invites=[{id:1,recipient:100004,expires_at:new Date(Date.now()+5*86400000).toISOString(),created_at:now}];
const region={id:'fra',city:'Франкфурт',country:'DE'},plan={id:'vc2-1c-1gb',bandwidth:1024},price={monthly_cost:5,hourly_cost:.007};
const ops=[{id:'demo-fra',instance_id:'demo-instance',exit_id:'fra',offer:{region,plan,price},state:'ready',phase:'ready',charged:true}];
let preferred=null;
const exits=[{id:'ams',display_name:'Нидерланды · Амстердам',reachable:true},{id:'fra',display_name:'Германия · Франкфурт',reachable:true}];
const state=new URLSearchParams(location.search).get('state');
if(state==='disabled')people[0].active=false;if(state==='pending')people[0].pending=true;
window.fetch=async (path,options={})=>{
 let body={};try{body=JSON.parse(options.body||'{}')||{}}catch{}
 let value,status=200;
 if(path==='/api/me')value={is_admin:true};
 else if(path==='/api/self')value={registered:state!=='new',is_admin:true,member:people[0]};
 else if(path==='/api/self/subscription')value={url:'https://example.invalid/demo-subscription',import_url:'https://example.invalid/demo-import'};
 else if(path==='/api/self/exits')value={exits,selected_exit_id:preferred,effective_exit_id:preferred||'ams',profiles:exits.map(e=>({name:e.display_name,effective_exit_id:e.id}))};
 else if(path==='/api/self/exit-selection'){preferred=body.exit_id;value={};}
 else if(path==='/api/members')value=people;
 else if(/^\/api\/members\/\d+\/action$/.test(path)){const person=people.find(p=>String(p.telegram_id)===path.split('/')[3]);if(person){if(body.action==='reset')person.uuid+='-reset';else person.active=body.action==='enable';person.pending=false;value=person}else status=404;}
 else if(path==='/api/enrollment/group'){if(options.method==='PUT')group={...group,...body};value=group;}
 else if(path==='/api/enrollment/invites'){if(options.method==='POST'){invites.unshift({id:Date.now(),recipient:body.recipient,expires_at:new Date(Date.now()+7*86400000).toISOString()});value={url:'https://example.invalid/demo-invite'}}else value=invites;}
 else if(path.includes('/api/enrollment/invites/')&&path.endsWith('/cancel')){const i=invites.find(i=>String(i.id)===path.split('/')[4]);if(i)i.cancelled_at=now;value={};}
 else if(path==='/api/enrollment/picker'){alert('В рабочем боте здесь появится штатный выбор Telegram-аккаунта. Макет не отправляет сообщения.');value={};}
 else if(path==='/api/cloud/operations')value=ops;
 else if(path==='/api/cloud/replicas')value=[{id:'ams',name:'Амстердам',state:'streaming',free_bytes:22*1073741824,required_bytes:5*1073741824},{id:'fra',name:'Франкфурт',state:'syncing',free_bytes:18*1073741824,required_bytes:5*1073741824}];
 else if(path==='/api/cloud/catalog')value={regions:[region,{id:'ams',city:'Амстердам',country:'NL'},{id:'waw',city:'Варшава',country:'PL'}],plans:[plan]};
 else if(path==='/api/cloud/offers')value={id:'demo-offer',region:body.region==='fra'?region:{id:body.region,city:body.region==='ams'?'Амстердам':'Варшава'},plan,price};
 else if(path.endsWith('/confirm')){alert('Это макет: VPS не покупается и реальные средства не списываются.');value={};}
 else if(path.startsWith('/api/cloud/operations/')&&path.endsWith('/action')){const op=ops.find(o=>o.id===path.split('/')[4]);if(op){op.state=body.action==='delete'?'deleted':'pending';op.phase=body.action==='delete'?'cleanup':'verify';}value={};}
 else{status=503;value={};}
 return {ok:status===200,status,json:async()=>JSON.parse(JSON.stringify(value||{}))};
};
window.Telegram={WebApp:{ready(){},expand(){},initData:'',openLink(){alert('В рабочем кабинете эта кнопка откроет импорт вашей подписки в Happ. В макете ключей VPN нет.');},close(){}}};
document.addEventListener('click',event=>{const link=event.target.closest('a');if(!link)return;const href=link.getAttribute('href');if(href==='/')link.href='admin.html';else if(href==='/member')link.href='member.html';else if(href==='/#invites')link.href='admin.html#invites';else if(href?.startsWith('/legacy.html')){event.preventDefault();alert('Диагностика, статистика и старые конфиги: содержимое этого раздела ещё дорабатывается.');}});
})();
