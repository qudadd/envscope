// Fixed desktop actions. No user input becomes an executable or shell command.
const $=id=>document.getElementById(id);
const LABELS={install:"安装维护核心与后台保护",uninstall:"卸载原版维护组件",status:"读取原版账号状态",check:"原版概要检测",checkdetail:"原版完整检测",fix:"修复环境", "update-check":"检查维护核心更新","update-apply":"更新维护核心","set-region":"按出口重设系统地区","set-client":"更换原版代理客户端",fingerprint:"设备信息","cli-info":"CLI 安装信息","open-safe":"打开临时浏览器","snapshot-export":"导出加密 DMG","snapshot-import":"导入加密 DMG","diagnose-proxy":"原版代理诊断"};
const VERDICTS={blocked:"发现策略违反",incomplete:"检测尚不完整",review:"需要复核",clear_in_scope:"配置范围内通过"};
const STATES={completed:"操作完成",started:"已提交启动请求，请查看外部窗口",failed:"操作未完成",blocked:"操作已阻止",confirmation_required:"需要确认",unsupported:"当前系统不支持",unavailable:"维护核心尚未就绪",rejected:"输入未通过验证"};
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const cell=(row,text)=>{const n=el("td",text);row.append(n);return n;};
const table=headers=>{const t=el("table"),head=el("thead"),r=el("tr");for(const h of headers)r.append(el("th",h));head.append(r);const body=el("tbody");t.append(head,body);return [t,body];};
const button=(text,fn)=>{const b=el("button",text,"link");b.type="button";b.addEventListener("click",fn);return b;};

export async function initDesktopControls({sessionPromise,onReport,download}) {
  const session=await sessionPromise;if(!session)return;
  $("desktop-nav").hidden=false;
  let catalog=null,busy=false;
  function page(name){
    for(const n of document.querySelectorAll(".page"))n.hidden=n.id!=="page-"+name;
    for(const n of document.querySelectorAll(".tab")){if(n.dataset.page===name)n.setAttribute("aria-current","page");else n.removeAttribute("aria-current");}
  }
  for(const n of document.querySelectorAll(".tab"))n.addEventListener("click",()=>page(n.dataset.page));
  async function refresh(){
    const response=await fetch("/api/catalog",{headers:{"X-EnvScope-Token":session.token},cache:"no-store"});
    if(!response.ok)throw new Error("无法读取本机功能列表");
    catalog=await response.json();renderAccounts();renderHistory();renderSettings();renderMaintenance();
    const options=[el("option","手动填写")];options[0].value="";
    for(const proxy of catalog.proxies||[]){const option=el("option",proxy.url+" · "+proxy.sources.join(" / "));option.value=proxy.url;options.push(option);}
    $("proxy-found").replaceChildren(...options);
    if(!$("proxy-url").value&&catalog.proxies?.length===1)$("proxy-url").value=catalog.proxies[0].url;
    if(options.some(o=>o.value===$("proxy-url").value))$("proxy-found").value=$("proxy-url").value;
  }
  async function action(id,params={},output="tool-output",confirmation=null){
    if(busy){$(output).textContent="已有操作进行中，请稍候。";return null;}
    const descriptor=catalog?.legacy.actions.find(a=>a.id===id);
    const needsConfirmation=confirmation!==null||descriptor?.requires_confirmation===true;
    const effects=confirmation||descriptor?.effects?.join("\n")||"此操作会修改本机资料。";
    if(needsConfirmation&&!window.confirm(effects+"\n\n继续执行？"))return null;
    busy=true;$(output).textContent=["account-switch","app-launch","open-safe"].includes(id)?"正在重新检测启动条件，请稍候…":"正在执行，请稍候…";
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),240000);
    try {
      const response=await fetch("/api/action",{method:"POST",signal:controller.signal,headers:{"Content-Type":"application/json","X-EnvScope-Token":session.token},
        body:JSON.stringify({action:id,params,confirmed:needsConfirmation})});
      const result=await response.json();
      if(!response.ok)throw new Error(result.error||"操作无法完成");
      if(result.latest_report)onReport(result.latest_report);
      if(result.state==="completed"&&["settings-save","settings-restore"].includes(id))$(output).textContent=id==="settings-save"?"已保存，后续检测使用新偏好。":"已恢复上次偏好。";
      else if(result.state==="completed"&&id==="account-label")$(output).textContent="账号名称已保存。";
      else if(result.state==="completed"&&id==="account-switch")$(output).textContent="已准备槽位 "+result.result.slot+(result.result.launched?"，已提交应用启动请求。":"，应用未启动，请查看安装状态。")+(result.result.warnings?.length?"\n"+result.result.warnings.join("\n"):"");
      else if(result.state==="completed"&&id==="support-bundle")$(output).textContent="诊断包已导出，分享前请复核。";
      else if(result.state==="completed"&&id==="history-report")$(output).textContent="已读取历史结果。";
      else if(result.state==="completed"&&id==="proxy-diagnose")$(output).textContent=result.evidence.map(o=>(o.endpoint||"测试端点")+"\nHTTP "+o.http_status+" · "+({access_denied:"拒绝访问",rate_limited:"请求限流",authentication_required:"需要认证",http_success_only:"已收到成功响应",transport_unverified:"连接未验证",server_error:"服务错误",redirect_not_followed:"重定向未跟随"}[o.access]||o.access)+(o.elapsed_ms!==undefined?" · "+o.elapsed_ms+" ms":"")).join("\n\n")+"\n\n"+(result.boundary||"");
      else if(result.stdout!==undefined)$(output).textContent=(STATES[result.state]||result.state)+"\n原版输出（未独立验证）\n"+result.stdout+"\n"+(result.stderr||result.reason||"");
      else if(result.state==="blocked")$(output).textContent="操作已阻止。\n"+(result.reason||"")+"\n"+(result.reasons||[]).join("\n");
      else {const display={...result};delete display.latest_report;$(output).textContent=(STATES[result.state]||result.state||"")+"\n"+JSON.stringify(display,null,2);}
      if(result.bundle)download(result.bundle,"support");
      await refresh();return result;
    }catch(error){$(output).textContent=error.name==="AbortError"?"等待已超时。操作可能仍在后台执行；请查看实际状态，避免重复执行。":String(error.message);return null;}
    finally{clearTimeout(timer);busy=false;}
  }
  function renderAccounts(){
    const value=catalog.accounts;
    $("account-note").textContent=value.error|| (value.pending?.length?"发现未完成的事务，已保留所有副本并阻止切换。请检查："+value.pending.join("、"):
      value.current?"当前槽位："+value.current:"首次切换会把现有资料归入 A；新槽位首次打开后需要登录。");
    const [t,body]=table(["槽位","名称","状态","存档大小",""]);
    for(const a of value.accounts){const r=el("tr");cell(r,a.slot);cell(r,a.label||"—");cell(r,({active:"当前",archived:"已有存档",empty:"待登录",recovery_required:"需恢复"})[a.state]||a.state);
      cell(r,a.bytes===null?"—":(a.bytes/1048576).toFixed(1)+" MB");const c=cell(r,"");
      const b=button(a.is_current?"打开":"切换",()=>action("account-switch",{slot:a.slot},"account-output","将重新检测环境、退出 Claude，并交换账号配置。请先保存应用内工作。"));
      b.disabled=!!value.pending?.length;c.append(b,button("命名",()=>{const label=window.prompt("账号名称",a.label||"");if(label!==null)void action("account-label",{slot:a.slot,label},"account-output");}));body.append(r);
    }$("account-list").replaceChildren(t);
  }
  function renderHistory(){
    const history=catalog.history||[],[t,body]=table(["检测时间","结果",""]);
    for(const h of [...history].reverse()){const r=el("tr");cell(r,new Date(h.created_at).toLocaleString());cell(r,VERDICTS[h.verdict]||h.verdict);
      cell(r,"").append(button("查看",async()=>{const result=await action("history-report",{id:h.id},"history-output");if(result?.report){onReport(result.report);page("audit");$("session-state").textContent="正在查看历史结果，启动时仍会重新检测";}}));body.append(r);}
    $("history-list").replaceChildren(history.length?t:el("p","尚无检测记录。","note"));
    for(const name of ["before","after"]){const select=$("history-"+name);select.replaceChildren(...history.map(h=>{const o=el("option",new Date(h.created_at).toLocaleString());o.value=h.id;return o;}));}
    if(history.length){$("history-after").value=history.at(-1).id;$("history-before").value=history.at(-2)?.id||history.at(-1).id;}
    $("history-compare").disabled=history.length<2;
  }
  function renderSettings(){
    const form=$("settings-form");for(const [key,value] of Object.entries(catalog.settings)){const field=form.elements.namedItem(key);if(!field)continue;
      if(field.type==="checkbox")field.checked=value;else field.value=Array.isArray(value)?value.join("\n"):value;}
  }
  function renderMaintenance(){
    const l=catalog.legacy,select=$("maintenance-action"),previous=select.value;
    select.replaceChildren(...l.actions.filter(a=>LABELS[a.id]&&!["cli-info","fingerprint","diagnose-proxy"].includes(a.id)).map(a=>{
      const o=el("option",LABELS[a.id]+(!a.supported?" · 此系统不支持":!a.available?" · 需安装":""));o.value=a.id;return o;
    }));
    if([...select.options].some(o=>o.value===previous))select.value=previous;
    $("backend-note").textContent=(l.backend.installed?"已发现已安装的原版维护核心。":"尚未安装维护核心，可从下方安装。")+" 随附源码校验："+(l.vendor.verified?"通过":"未通过，安装已禁用")+"。";
    setParameters();
  }
  function setParameters(){
    const id=$("maintenance-action").value,a=catalog.legacy.actions.find(a=>a.id===id);
    $("maintenance-effects").replaceChildren(...(a?.effects||[]).map(text=>el("p",text)));
    $("maintenance-run").disabled=!a?.available;
    $("maintenance-availability").textContent=!a?.supported?"此平台的原版未提供此功能":!a.available?"需要先安装支持该操作的维护核心":"";
    $("param-client").hidden=id!=="set-client";
    $("param-policy").hidden=id!=="fix"||catalog.legacy.platform!=="Darwin";
    $("param-url").hidden=id!=="open-safe";
    $("param-snapshot").hidden=!["snapshot-export","snapshot-import"].includes(id);
  }
  $("account-add").addEventListener("click",()=>action("account-label",{slot:$("new-slot").value.trim(),label:$("new-label").value.trim()||$("new-slot").value.trim()},"account-output"));
  for(const id of ["account-export","account-import"])$(id).addEventListener("click",()=>action(id,{slot:$("archive-slot").value.trim(),file:$("archive-path").value.trim()},"account-output",
    id==="account-export"?"将创建未加密的账号目录备份。文件含登录资料，请保存在受保护的本机目录。":"将读取指定目录并导入空的非活动槽位。不会覆盖现有槽位。"));
  $("proxy-found").addEventListener("change",()=>{$("proxy-url").value=$("proxy-found").value;});
  $("proxy-test").addEventListener("click",()=>action("proxy-diagnose",{proxy:$("proxy-url").value.trim()}));
  $("cli-info").addEventListener("click",()=>action("cli-info"));$("device-info").addEventListener("click",()=>action("fingerprint"));
  $("support-bundle").addEventListener("click",()=>action("support-bundle"));
  $("browser-info").addEventListener("click",async()=>{
    const result={language:navigator.languages,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,screen:{width:screen.width,height:screen.height,colorDepth:screen.colorDepth},hardwareThreads:navigator.hardwareConcurrency||null};
    try{const canvas=document.createElement("canvas");canvas.width=220;canvas.height=40;const c=canvas.getContext("2d");c.font="16px sans-serif";c.fillText("EnvScope 0123456789",3,24);
      const bytes=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(canvas.toDataURL()));result.canvas_sha256=[...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,"0")).join("");
    }catch{result.canvas_sha256="unavailable";}
    try{const gl=document.createElement("canvas").getContext("webgl");const ext=gl?.getExtension("WEBGL_debug_renderer_info");result.webgl=ext?{vendor:gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),renderer:gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)}:"unavailable_or_limited";gl?.getExtension("WEBGL_lose_context")?.loseContext();}
    catch{result.webgl="unavailable";}
    $("tool-output").textContent="仅在本页展示，未上传。指纹差异不构成账号风险结论。\n"+JSON.stringify(result,null,2);
  });
  $("maintenance-action").addEventListener("change",setParameters);
  $("maintenance-run").addEventListener("click",async()=>{
    const id=$("maintenance-action").value,params={};
    if(id==="set-client")params.client=$("legacy-client").value;
    if(id==="fix"&&catalog.legacy.platform==="Darwin")params.webrtc_policy=$("legacy-policy").value;
    if(id==="open-safe")params.url=$("safe-url").value;
    if(["snapshot-export","snapshot-import"].includes(id))Object.assign(params,{account:$("snapshot-account").value,file:$("snapshot-file").value,password:$("snapshot-password").value});
    try{await action(id,params);}finally{$("snapshot-password").value="";}
  });
  $("history-compare").addEventListener("click",async()=>{
    const result=await action("history-compare",{before:$("history-before").value,after:$("history-after").value},"history-output");
    if(result)$("history-output").textContent=(result.observed_address_set_changed===null?"出口证据不足，无法比较":result.observed_address_set_changed?"两次观测的出口集合不同":"两次观测的出口集合相同")+"\n"+(result.changes.length?JSON.stringify(result.changes,null,2):"各检查项状态未变。")+"\n"+result.note;
  });
  $("settings-form").addEventListener("submit",event=>{
    event.preventDefault();const params={},form=event.currentTarget;
    for(const field of form.elements){if(!field.name)continue;params[field.name]=field.type==="checkbox"?field.checked:field.name.startsWith("allowed_")?field.value.split(/[\s,;]+/).filter(Boolean):field.value.trim();}
    void action("settings-save",params,"settings-output");
  });
  $("settings-restore").addEventListener("click",()=>action("settings-restore",{},"settings-output"));
  document.addEventListener("envscope-audit-complete",()=>{void refresh().catch(()=>{});});
  try{await refresh();}catch(error){$("backend-note").textContent=error.message;}
}
