// HTTPS SERVER backend - Render (Node 18+) + Supabase. Env: SUPABASE_URL, SUPABASE_SERVICE_KEY, ADMIN_PASSWORD
const http=require('http');
const {SUPABASE_URL:SB,SUPABASE_SERVICE_KEY:SK,ADMIN_PASSWORD,PORT=3000}=process.env;
const H={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type,X-Admin','Content-Type':'application/json'};
const hd={apikey:SK,'Content-Type':'application/json',...(String(SK).startsWith('eyJ')?{Authorization:'Bearer '+SK}:{})};
const db=async(path,o={})=>{const r=await fetch(SB+'/rest/v1/'+path,{...o,headers:{...hd,...(o.headers||{})}});
  if(!r.ok)throw new Error(r.status+' '+await r.text());const t=await r.text();return t?JSON.parse(t):null};
const enc=encodeURIComponent,patch=(k,body)=>db('licenses?key=eq.'+enc(k),{method:'PATCH',body:JSON.stringify(body)});
const norm=k=>String(k||'').replace(/\s/g,'').toUpperCase();
const dig=c=>String(c||'').replace(/\D/g,'');
const crypto=require('crypto');
const rnd=(a,n)=>[...crypto.randomBytes(n*2)].slice(0,n).map(x=>a[x%a.length]).join('');
const ALPHA='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const bad=new Map();
const hits=ip=>{const n=(bad.get(ip)||[]).filter(t=>Date.now()-t<6e5);bad.set(ip,n);return n};
const DEF={telegram:'KINGAI_BOT',price:1879,order:'ORDER LICENCE FOR HTTPS BASIC - 1879'};
const settings=async()=>{const s=(await db('settings?id=eq.1&select=*'))[0];return s?{telegram:s.telegram,price:s.price,order:s.order_text}:DEF};

async function check(b,ip,needCode){
  const n=hits(ip);if(n.length>=15)return{e:'too_many'};
  const k=norm(b.key),v=(await db('licenses?key=eq.'+enc(k)+'&select=*'))[0];
  if(!v){n.push(Date.now());return{e:'invalid'}}
  if(v.server!==b.server)return{e:'wrong_server'};
  if(needCode&&dig(b.code)!==v.code){n.push(Date.now());return{e:'bad_code'}}
  if(!v.act){v.act=Date.now();await patch(k,{act:v.act})}
  const exp=v.act+v.days*864e5;
  return exp<=Date.now()?{e:'expired'}:{v,k,exp}}

function cleanUrl(u){u=String(u||'').trim();if(!u.includes('://'))u='https://'+u;
  try{const x=new URL(u),h=x.hostname.toLowerCase();
    return /^https?:$/.test(x.protocol)&&/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(h)?x.protocol+'//'+h:null}catch{return null}}

http.createServer(async(req,res)=>{
  const send=(o,s=200)=>{res.writeHead(s,H);res.end(JSON.stringify(o))};
  try{
    if(req.method==='OPTIONS'){res.writeHead(204,H);return res.end()}
    const p=new URL(req.url,'http://x').pathname,ip=(req.headers['x-forwarded-for']||req.socket.remoteAddress||'x').split(',')[0].trim();
    if(p==='/')return send({ok:true});
    if(p==='/api/settings')return send(await settings());
    if(req.method!=='POST')return send({error:'not found'},404);
    let raw='';for await(const c of req){raw+=c;if(raw.length>4096)break}
    let b={};try{b=JSON.parse(raw)}catch{}
    const fail=r=>send({ok:false,error:r.e});
    if(p==='/api/verify'){const r=await check(b,ip);return r.e?fail(r):send({ok:true,expires:r.exp,server:r.v.server})}
    if(p==='/api/connect'){const r=await check(b,ip,1);return r.e?fail(r):send({ok:true,expires:r.exp,urls:r.v.urls})}
    if(p==='/api/site'){const r=await check(b,ip,1);if(r.e)return fail(r);
      const u=cleanUrl(b.url);if(!u)return send({ok:false,error:'bad_url'});
      if(!r.v.urls.includes(u)){if(r.v.urls.length>=10)return send({ok:false,error:'limit'});r.v.urls.push(u);await patch(r.k,{urls:r.v.urls})}
      return send({ok:true,urls:r.v.urls})}
    if(p.startsWith('/api/admin/')){
      const n=hits(ip);if(n.length>=15)return send({ok:false,error:'too_many'},429);
      if(!ADMIN_PASSWORD||req.headers['x-admin']!==ADMIN_PASSWORD){n.push(Date.now());return send({ok:false,error:'auth'},401)}
      if(p==='/api/admin/add'){
        const days=Math.min(3650,Math.max(1,parseInt(b.days)||30)),server=b.server==='BASIC'?'BASIC':'ALL',cnt=Math.min(50,Math.max(1,parseInt(b.count)||1)),keys=[];
        for(let i=0;i<cnt;i++)keys.push({key:'HS-'+[1,2,3].map(()=>rnd(ALPHA,4)).join('-'),server,days,code:rnd('0123456789',12),act:0,urls:[],created:Date.now()});
        await db('licenses',{method:'POST',headers:{Prefer:'return=minimal'},body:JSON.stringify(keys)});
        return send({ok:true,keys})}
      if(p==='/api/admin/list')return send({ok:true,keys:await db('licenses?select=*&order=created.desc')});
      if(p==='/api/admin/del'){await db('licenses?key=eq.'+enc(norm(b.key)),{method:'DELETE'});return send({ok:true})}
      if(p==='/api/admin/settings'){
        const t=String(b.telegram||'').trim().replace(/^.*[\/@]/,'');
        if(!/^[A-Za-z0-9_]{5,32}$/.test(t))return send({ok:false,error:'bad_telegram'});
        const s={id:1,telegram:t,price:Math.max(0,parseInt(b.price)||DEF.price),order_text:String(b.order||DEF.order).slice(0,200)};
        await db('settings',{method:'POST',headers:{Prefer:'resolution=merge-duplicates,return=minimal'},body:JSON.stringify(s)});
        return send({ok:true,settings:{telegram:s.telegram,price:s.price,order:s.order_text}})}
    }
    send({error:'not found'},404)
  }catch(e){console.error(e.message);send({ok:false,error:'server_error'},500)}
}).listen(PORT,()=>console.log('listening',PORT));
