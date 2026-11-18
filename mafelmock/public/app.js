const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,opt={}){
  const h={...(opt.headers||{})};const t=sessionStorage.getItem('tok');if(t)h.authorization='Bearer '+t;
  if(opt.json){h['content-type']='application/json';opt.body=JSON.stringify(opt.json)}
  const r=await fetch('/api/'+path,{...opt,headers:h});const d=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(d.error||'Hata');return d}
