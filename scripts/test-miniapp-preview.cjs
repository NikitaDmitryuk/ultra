const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const file=require('node:path').join(__dirname,'../internal/bot/embed/miniapp/preview/demo.js');
const c={window:{},location:{search:''},URLSearchParams,document:{addEventListener(){}},alert(){}};
vm.runInNewContext(fs.readFileSync(file,'utf8'),c);
(async()=>{
 const request=async(p,body)=>{const r=await c.window.fetch(p,{method:body?'POST':'GET',body:JSON.stringify(body)});return [r.status,await r.json()]};
 assert.equal((await request('/api/self'))[1].member.telegram_id,100001);
 await request('/api/members/100001/action',{action:'disable'});
 assert.equal((await request('/api/self'))[1].member.active,false);
 assert.equal((await request('/api/cloud/offers/demo/confirm',{}))[0],200);
 assert.equal((await request('https://real-service.invalid/private',{}))[0],503);
 console.log('preview: local actions and network isolation passed');
})();
