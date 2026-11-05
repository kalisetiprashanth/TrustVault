const $ = (id) => document.getElementById(id);
function cookie(name){return document.cookie.split("; ").find(x=>x.startsWith(name+"="))?.split("=").slice(1).join("=")||""}
function csrf(){return decodeURIComponent(cookie("tv_csrf"))}
async function api(url, options={}) {
  options.credentials="same-origin";
  options.headers=options.headers||{};
  if(!["GET","HEAD"].includes((options.method||"GET").toUpperCase())) options.headers["X-CSRF-Token"]=csrf();
  const res=await fetch(url,options);
  let body={};try{body=await res.json()}catch{}
  if(!res.ok) throw new Error(body.detail||"Request failed");
  return body;
}
function message(id,text,error=false){const el=$(id);if(!el)return;el.textContent=text;el.classList.toggle("error",error)}
async function loadDashboard(){
  let me;try{me=await api("/users/me")}catch{location.href="/";return}
  $("whoami").textContent=`${me.full_name} · ${me.username}`;
  $("rolePill").textContent=me.role.toUpperCase();$("roleStat").textContent=me.role;
  if(me.role==="owner")$("uploadPanel").classList.remove("hidden");
  if(me.role==="admin")$("adminPanel").classList.remove("hidden");
  await loadDocs();
  if(me.role==="admin")await loadAdmin();
}
async function loadDocs(params=""){
  try{const docs=await api("/documents"+params);$("docCount").textContent=docs.length;
    $("documentsBody").innerHTML="";
    if(!docs.length){$("documentsBody").innerHTML='<tr><td colspan="5" class="muted">No documents available to this account.</td></tr>';return}
    docs.forEach(d=>{const tr=document.createElement("tr");
      const name=document.createElement("td");name.textContent=d.name;
      const cat=document.createElement("td");cat.textContent=d.category;
      const size=document.createElement("td");size.textContent=(d.size_bytes/1024).toFixed(1)+" KB";
      const date=document.createElement("td");date.textContent=new Date(d.updated_at).toLocaleString();
      const actions=document.createElement("td");const link=document.createElement("a");link.className="table-action";link.href="/documents/"+encodeURIComponent(d.id)+"/download";link.textContent="Download";link.addEventListener("click",async e=>{e.preventDefault();try{const r=await fetch(link.href,{credentials:"same-origin"});if(!r.ok){const b=await r.json();throw new Error(b.detail||"Download denied")}const blob=await r.blob();const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=d.name;a.click();URL.revokeObjectURL(a.href)}catch(err){message("documentMessage",err.message,true)}});
      actions.append(link);
      const trash=document.createElement("button");trash.className="btn ghost";trash.textContent="Delete";trash.onclick=async()=>{if(!confirm("Delete this document permanently?"))return;try{await api("/documents/"+encodeURIComponent(d.id),{method:"DELETE"});await loadDocs();}catch(e){message("documentMessage",e.message,true)}};
      actions.append(trash);tr.append(name,cat,size,date,actions);$("documentsBody").append(tr);
    });
  }catch(e){message("documentMessage",e.message,true)}
}
async function loadAdmin(){
  try{
    const logs=await api("/admin/audit-logs?limit=100");
    $("auditBody").innerHTML="";
    logs.forEach(l=>{const tr=document.createElement("tr");[new Date(l.created_at).toLocaleString(),l.actor_id||"Anonymous",l.action,l.document_id||"—",l.outcome].forEach(v=>{const td=document.createElement("td");td.textContent=v;tr.append(td)});$("auditBody").append(tr)});
    const summary=await api("/admin/activity-summary");$("activitySummary").innerHTML="";
    summary.forEach(s=>{const div=document.createElement("div");div.className="activity-card";div.textContent=`${s.action} · ${s.outcome}: ${s.total}`;$("activitySummary").append(div)});
  }catch(e){message("auditVerifyMessage",e.message,true)}
}
if($("loginForm"))$("loginForm").addEventListener("submit",async e=>{e.preventDefault();const fd=new FormData(e.target);try{await api("/auth/login",{method:"POST",body:fd});location.href="/static/dashboard.html"}catch(err){message("loginMessage",err.message,true)}});
if($("logoutBtn"))$("logoutBtn").onclick=async()=>{try{await api("/auth/logout",{method:"POST"});location.href="/"}catch(e){alert(e.message)}};
if($("uploadForm"))$("uploadForm").onsubmit=async e=>{e.preventDefault();try{await api("/documents/upload",{method:"POST",body:new FormData(e.target)});e.target.reset();message("uploadMessage","Document uploaded.");await loadDocs()}catch(err){message("uploadMessage",err.message,true)}};
if($("searchForm"))$("searchForm").onsubmit=async e=>{e.preventDefault();const p=new URLSearchParams(new FormData(e.target));await loadDocs("?"+p.toString())};
if($("refreshBtn"))$("refreshBtn").onclick=()=>loadDocs();
if($("verifyAudit"))$("verifyAudit").onclick=async()=>{try{const r=await api("/admin/audit-verify");message("auditVerifyMessage",r.valid?`Audit chain valid · ${r.checked} entries checked`:`Audit chain broken at row ${r.broken_at}`,!r.valid)}catch(e){message("auditVerifyMessage",e.message,true)}};
if($("createUserForm"))$("createUserForm").onsubmit=async e=>{e.preventDefault();try{const r=await api("/admin/users",{method:"POST",body:new FormData(e.target)});message("createUserMessage",`Created ${r.username}`);e.target.reset()}catch(err){message("createUserMessage",err.message,true)}};
if($("whoami"))loadDashboard();
