// Fixed desktop actions. No user input becomes an executable or shell command.
import {describeProxy} from './diagnosis.mjs';
import {DISCONNECTED, disconnected} from './connection.mjs';
const $=id=>document.getElementById(id);
const LABELS={install:"安装维护核心与后台保护",uninstall:"卸载原版维护组件",status:"读取原版账号状态",check:"原版概要检测",checkdetail:"原版完整检测",fix:"修复环境", "update-check":"检查维护核心更新","update-apply":"更新维护核心","set-region":"按出口重设系统地区","set-client":"更换原版代理客户端",fingerprint:"设备信息","cli-info":"CLI 安装信息","open-safe":"打开临时浏览器","snapshot-export":"导出加密 DMG","snapshot-import":"导入加密 DMG","diagnose-proxy":"原版代理诊断"};
const VERDICTS={blocked:"发现策略违反",incomplete:"检测尚不完整",review:"需要复核",clear_in_scope:"配置范围内通过"};
const STATES={completed:"操作完成",started:"已提交启动请求，请查看外部窗口",failed:"操作未完成",blocked:"操作已阻止",confirmation_required:"需要确认",unsupported:"当前系统不支持",unavailable:"维护核心尚未就绪",rejected:"输入未通过验证"};
Object.assign(LABELS,{'legacy-cli-info':'原版 CLI 详细检查（macOS）','legacy-fingerprint':'原版设备详细检查（macOS）'});
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const cell=(row,text)=>{const n=el("td",text);row.append(n);return n;};
const table=headers=>{const t=el("table"),head=el("thead"),r=el("tr");for(const h of headers)r.append(el("th",h));head.append(r);const body=el("tbody");t.append(head,body);return [t,body];};
const button=(text,fn)=>{const b=el("button",text,"link");b.type="button";b.addEventListener("click",fn);return b;};

export async function initDesktopControls({sessionPromise,onReport,download,retest}) {
  const session=await sessionPromise;if(!session)return;
  $("desktop-nav").hidden=false;
  let catalog=null,busy=false,lastReportId=null;
  function page(name){
    for(const n of document.querySelectorAll(".page"))n.hidden=n.id!=="page-"+name;
    for(const n of document.querySelectorAll(".tab")){if(n.dataset.page===name)n.setAttribute("aria-current","page");else n.removeAttribute("aria-current");}
    window.scrollTo(0,0);
  }
  for(const n of document.querySelectorAll(".tab"))n.addEventListener("click",()=>page(n.dataset.page));
  async function refresh(){
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
    try{
    const response=await fetch("/api/catalog",{signal:controller.signal,headers:{"X-EnvScope-Token":session.token},cache:"no-store"});
    if(!response.ok)throw new Error("无法读取本机功能列表，请刷新状态或重新打开程序。");
    catalog=await response.json();renderAccounts();renderHistory();renderSettings();renderMaintenance();renderUpkeep(catalog.maintenance);renderBackups();$('catalog-error').hidden=true;
    document.dispatchEvent(new CustomEvent('envscope-catalog',{detail:{desktop:catalog.desktop,learning:catalog.learning,settings:catalog.settings,maintenance:catalog.maintenance,proxies:catalog.proxies,checks:catalog.checks,features:catalog.features}}));
    const options=[el("option","手动填写")];options[0].value="";
    for(const proxy of catalog.proxies||[]){const option=el("option",proxy.url+" · "+proxy.sources.join(" / "));option.value=proxy.url;options.push(option);}
    $("proxy-found").replaceChildren(...options);
    if(!$("proxy-url").value&&catalog.proxies?.length===1)$("proxy-url").value=catalog.proxies[0].url;
    if(options.some(o=>o.value===$("proxy-url").value))$("proxy-found").value=$("proxy-url").value;
    }catch(error){$('catalog-error').hidden=false;throw error;}finally{clearTimeout(timer);}
  }
  $('catalog-retry').addEventListener('click',async()=>{if(busy||$('start').disabled)return;try{await refresh();}catch{$('catalog-error').hidden=false;}});
  function information(value){
    const out=$('environment-output');out.replaceChildren(el('h3',value.title||'环境信息'));
    if(value.state==='partial')out.append(el('p','已显示可读取的资料，部分信息尚未取得。','note'));
    const list=el('dl');for(const row of value.rows||[]){const item=el('div');item.append(el('dt',row.label),el('dd',String(row.value??'尚未取得')));list.append(item);}out.append(list);
    if(value.note)out.append(el('p',value.note,'note'));out.focus({preventScroll:true});out.scrollIntoView({block:'nearest'});
  }
  async function action(id,params={},output="tool-output",confirmation=null){
    if(document.documentElement.dataset.serviceConnected==='false'){$(output).textContent=DISCONNECTED;disconnected();return null;}
    if(document.documentElement.dataset.operationBusy==='true'||$('start').disabled){$(output).textContent="正在检测或处理，请等待本次完成。";return null;}
    if(busy){$(output).textContent="已有操作进行中，请稍候。";return null;}
    const descriptor=catalog?.legacy?.actions?.find(a=>a.id===id);
    const needsConfirmation=confirmation!==null||descriptor?.requires_confirmation===true;
    const effects=confirmation||descriptor?.effects?.join("\n")||"此操作会修改本机资料。";
    if(needsConfirmation&&confirmation!==true&&!window.confirm(effects+"\n\n继续执行？"))return null;
    const disabledBefore=[...document.querySelectorAll('#page-accounts button, #environment-tools button, #proxy-test, #maintenance-run, #browser-cleanup, #history-compare, #settings-form button')].map(node=>[node,node.disabled]);
    for(const [node] of disabledBefore)node.disabled=true;
    busy=true;document.documentElement.dataset.operationBusy='true';$('start').disabled=true;$(output).textContent=["account-switch","app-launch","open-safe"].includes(id)?"正在重新检测启动条件，请稍候…":"正在执行，请稍候…";
    $(output).scrollIntoView({block:'nearest'});
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),240000);
    try {
      const response=await fetch("/api/action",{method:"POST",signal:controller.signal,headers:{"Content-Type":"application/json","X-EnvScope-Token":session.token},
        body:JSON.stringify({action:id,params,confirmed:needsConfirmation})});
      const result=await response.json();
      if(!response.ok)throw new Error(({invalid_session:'本地会话已失效，请重新打开 EnvScope。',audit_running:'正在进行其他检测或操作，请等待完成。',operation_unavailable_or_deadline:'本次读取未能完成，请稍后重试；不影响其他功能。'})[result.error]||result.error||"操作无法完成");
      if(result.latest_report)onReport(result.latest_report);
      if(id==='archive-choose-file'){if(result.file)$('encrypted-path').value=result.file;$(output).textContent=result.reason||(result.file?'文件位置已选择。':'已取消选择。');}
      else if(['archive-export','archive-import','browser-cleanup','open-safe'].includes(id))$(output).textContent=[result.reason,result.boundary].filter(Boolean).join('\n');
      else if(['cli-info','fingerprint'].includes(id)&&result.rows)information(result);
      else if(id.startsWith('maintenance-'))$(output).textContent=result.reason||({planned:'方案已生成，请核对下方影响。',enabled:'持续维护已启用。',disabled:'持续维护已停用。',completed:'已刷新维护结果。',confirmation_required:'请先审核方案并确认。'})[result.state]||'本次操作尚未确认完成。';
      else if(result.state==="completed"&&["settings-save","settings-restore"].includes(id))$(output).textContent=id==="settings-save"?"已保存，后续检测使用新偏好。":"已恢复上次偏好。";
      else if(result.state==="completed"&&id==="account-label")$(output).textContent="账号名称已保存。";
      else if(result.state==="completed"&&id==="account-switch")$(output).textContent="已准备槽位 "+result.result.slot+(result.result.launched?"，已提交应用启动请求。":"，应用未启动，请查看安装状态。")+(result.result.warnings?.length?"\n"+result.result.warnings.join("\n"):"");
      else if(id==='app-launch')$(output).textContent=[result.reason,...result.reasons||[]].filter(Boolean).join('\n');
      else if(result.state==="completed"&&id==="support-bundle")$(output).textContent="诊断包已导出，分享前请复核。"+(!result.bundle?.report?' 本轮尚无检测报告，包内仅含设置与维护能力信息。':'');
      else if(result.state==="completed"&&id==="history-report")$(output).textContent="已读取历史结果。";
      else if(result.state==="completed"&&id==="proxy-diagnose")$(output).textContent=result.evidence.map(describeProxy).join("\n\n")+"\n\n"+(result.boundary||"");
      else if(result.stdout!==undefined)$(output).textContent=(STATES[result.state]||result.state)+"\n原版输出（未独立验证）\n"+result.stdout+"\n"+(result.stderr||result.reason||"");
      else if(result.state==="blocked")$(output).textContent="操作已阻止。\n"+(result.reason||"")+"\n"+(result.reasons||[]).join("\n");
      else {const display={...result};delete display.latest_report;$(output).textContent=(STATES[result.state]||result.state||"")+"\n"+JSON.stringify(display,null,2);}
      if(result.bundle)download(result.bundle,"support");
      // Information reads do not mutate the catalog; don't turn a successful
      // display into an error just because an unrelated catalog refresh fails.
      if(!['cli-info','fingerprint','support-bundle','proxy-diagnose'].includes(id)){
        try{await refresh();}catch{$(output).append(el('p','操作已返回，但功能列表刷新失败。请重新打开程序核对状态。','note'));}
      }return result;
    }catch(error){if(error instanceof TypeError){disconnected();$(output).textContent=DISCONNECTED;}else $(output).textContent=error.name==="AbortError"?"等待已超时。操作可能仍在后台执行；请查看实际状态，避免重复执行。":String(error.message);return null;}
    finally{clearTimeout(timer);busy=false;document.documentElement.dataset.operationBusy='false';$('start').disabled=false;for(const [node,disabled] of disabledBefore)if(node.isConnected)node.disabled=disabled;if(catalog)renderAccounts();}
  }
  function renderAccounts(){
    const value=catalog.accounts;
    $("account-note").textContent=value.error|| (value.pending?.length?"发现未完成的事务，已保留所有副本并阻止切换。请检查："+value.pending.join("、"):
      value.current?"当前资料："+value.current+"。当前只代表已载入该资料，登录是否有效请在 Claude 中确认。":"尚未归档当前资料。首次使用会先将现有桌面资料保留为 A；不会自动注册账号。");
    const [t,body]=table(["槽位","名称","状态","存档大小",""]);
    for(const a of value.accounts){const r=el("tr");r.dataset.account=a.slot;cell(r,a.slot);cell(r,a.label||"未命名");cell(r,({active:"当前资料",archived:"已有存档",empty:"空资料",recovery_required:"需恢复"})[a.state]||a.state);
      cell(r,a.bytes===null?"—":(a.bytes/1048576).toFixed(1)+" MB");const c=cell(r,"");
      const first=!value.current&&a.slot==='A';
      const b=button(a.is_current?'打开当前账号':first?'保存当前资料到 A':a.has_snapshot?'切换并打开':'首次登录',()=>action(a.is_current?'app-launch':'account-switch',a.is_current?{}:{slot:a.slot},'account-output',
        a.is_current?'将重新检测并打开当前 Claude 桌面资料；登录有效性仍需在 Claude 中确认。':`请先保存 Claude 中的工作。将重新检测、退出桌面应用，再${first?'把现有资料归为 A':`保留当前资料并载入 ${a.label||a.slot}` }。${!value.current&&!first?'现有资料先保留在 A。':''}${!a.has_snapshot&&!first?'目标为空资料，需要在 Claude 中手动登录自己的另一个账号。':''}`));
      b.disabled=busy||!!value.pending?.length||!!value.error;const rename=button("命名",()=>{const label=window.prompt("显示名称（仅作本机备注，不是登录邮箱）",a.label||"");if(label!==null)void action("account-label",{slot:a.slot,label},"account-output");});rename.disabled=busy;c.append(b,rename);body.append(r);
    }$("account-list").replaceChildren(t);
  }
  function renderHistory(){
    const history=catalog.history||[],[t,body]=table(["检测时间","结果",""]);
    for(const h of [...history].reverse()){const r=el("tr");cell(r,new Date(h.created_at).toLocaleString());cell(r,VERDICTS[h.verdict]||h.verdict);
      cell(r,"").append(button("查看",async()=>{const result=await action("history-report",{id:h.id},"history-output");if(result?.report){onReport(result.report,'history');page("audit");$("session-state").textContent="正在查看历史结果，启动时仍会重新检测";}}));body.append(r);}
    $("history-list").replaceChildren(history.length?t:el("p","尚无检测记录。","note"));
    for(const name of ["before","after"]){const select=$("history-"+name);select.replaceChildren(...history.map(h=>{const o=el("option",new Date(h.created_at).toLocaleString());o.value=h.id;return o;}));}
    if(history.length){$("history-after").value=history.at(-1).id;$("history-before").value=history.at(-2)?.id||history.at(-1).id;}
    $("history-compare").disabled=history.length<2;
  }
  function renderSettings(){
    const form=$("settings-form");for(const [key,value] of Object.entries(catalog.settings)){const field=form.elements.namedItem(key);if(!field)continue;
      if(field.type==="checkbox")field.checked=value;else field.value=Array.isArray(value)?value.join("\n"):value;}
    $("usage").value=catalog.settings.usage||"auto";
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
    if(!catalog){$('maintenance-availability').textContent='功能列表尚未取得，请重新连接本地服务。';$('maintenance-run').disabled=true;return;}
    const id=$("maintenance-action").value,a=catalog.legacy.actions.find(a=>a.id===id);
    $("maintenance-effects").replaceChildren(...(a?.effects||[]).map(text=>el("p",text)));
    $("maintenance-run").disabled=!a?.available;
    $("maintenance-availability").textContent=id==='open-safe'?catalog.isolated_browser?.reason||'':!a?.supported?"此平台的原版未提供此功能":!a.available?"需要先安装支持该操作的维护核心":"";
    $("param-client").hidden=id!=="set-client";
    $("param-policy").hidden=id!=="fix"||catalog.legacy.platform!=="Darwin";
    $("param-url").hidden=id!=="open-safe";
    $("param-snapshot").hidden=!["snapshot-export","snapshot-import"].includes(id);
  }
  function renderUpkeep(value){
    if(!value)return;
    const states={disabled:'尚未启用持续维护',active:'最近一轮巡检已完成',attention:'巡检已完成，配置保持需要处理',waiting:'已注册，等待首次巡检',stale:'巡检已超期',failed:'最近一轮没有完成',schedule_unverified:'系统任务状态未确认',invalid:'维护记录无法核实'};
    $('upkeep-state').textContent=states[value.state]||'维护状态待核实';
    $('upkeep-status').textContent=[value.completed_at?'最近完成：'+new Date(value.completed_at).toLocaleString():'还没有完成记录。',value.enabled?`每 ${value.interval} 分钟复检。`:'',value.has_report?`${value.problem_count} 个待处理问题。`:'',value.auto_restore?(value.restore_note||'配置保持已选择，等待首次执行。'):'配置保持未开启。',value.reason].filter(Boolean).join(' ');
    const e=value.egress_48h||{};$('upkeep-egress').textContent=`48 小时有效出口观测 ${e.observations||0} 次，集合变化 ${e.changes||0} 次；变化本身不判定为账号风险。`;
    $('upkeep-run').disabled=!value.enabled;$('upkeep-stop').disabled=!value.enabled&&!value.scheduler?.present;$('upkeep-report').disabled=!value.has_report;
    $('quit').textContent=catalog.desktop?.mode==='native'?(value.enabled?'退出软件，定时维护继续':'退出 EnvScope'):(value.enabled?'结束界面，维护继续':'结束本地服务');
    const [t,body]=table(['时间','发生了什么','操作']);
    for(const event of [...value.events||[]].reverse()){
      const row=el('tr');cell(row,new Date(event.at).toLocaleString());cell(row,event.text);const controls=cell(row,'');
      for(const backup of event.backups||[]){const undo=button((backup.availability==='undone'?'已撤销 ':backup.availability==='changed'?'文件已变化，保留备份 ':'停用并撤销 ')+backup.label,async()=>{
        const result=await action('maintenance-undo',{backup_id:backup.id},'upkeep-output',true);
        if(result?.state==='completed')$('upkeep-output').textContent=result.reason;
      });undo.disabled=backup.availability!=='available';controls.append(undo);}body.append(row);
    }
    $('upkeep-events').replaceChildren(value.events?.length?t:el('p','尚无维护事件。','note'));
  }
  function renderBackups(){
    const records=catalog.config_backups||[],[t,body]=table(['备份时间','配置','恢复状态']);
    for(const record of records){
      const row=el('tr');cell(row,new Date(record.created_at).toLocaleString());cell(row,record.label);const control=cell(row,'');
      if(record.availability==='available')control.append(button('停用维护并撤销',async()=>{
        const result=await action('maintenance-undo',{backup_id:record.id},'tool-output',true);
        if(result?.state==='completed'){page('audit');if(retest)await retest();}
      }));
      else control.textContent=({undone:'已撤销',changed:'文件有后续修改，需手动合并',unavailable:'恢复证据不足，保留备份'})[record.availability]||'待核实';
      body.append(row);
    }
    $('config-backups').replaceChildren(records.length?t:el('p','尚无配置恢复记录。','note'));
  }
  $('upkeep-prepare').addEventListener('click',async()=>{
    $('upkeep-plan').replaceChildren();
    const value=await action('maintenance-plan',{report_id:lastReportId,interval:Number($('upkeep-interval').value),auto_restore:$('upkeep-restore').checked},'upkeep-output');
    if(value?.state!=='planned')return;
    const list=el('ul');for(const effect of value.effects)list.append(el('li',effect));
    const apply=button('确认启用持续维护',async()=>{
      apply.disabled=true;const result=await action('maintenance-enable',{plan_id:value.plan_id},'upkeep-output',true);
      $('upkeep-plan').replaceChildren();if(result?.state==='enabled')$('upkeep-output').textContent=result.reason;
    });
    $('upkeep-plan').append(el('h3','本次维护方案'),list,apply);
  });
  $('upkeep-run').addEventListener('click',async()=>{await action('maintenance-run',{},'upkeep-output');});
  $('upkeep-refresh').addEventListener('click',async()=>{await action('maintenance-status',{},'upkeep-output');});
  $('upkeep-stop').addEventListener('click',async()=>{await action('maintenance-disable',{},'upkeep-output',true);$('upkeep-plan').replaceChildren();});
  $('upkeep-report').addEventListener('click',async()=>{
    const value=await action('maintenance-report',{},'upkeep-output');
    if(value?.report){onReport(value.report,'maintenance');page('audit');$('session-state').textContent='正在查看后台原生巡检；浏览器与登录未测，处理前请重新检测。';}
  });
  $("account-add").addEventListener("click",async()=>{
    const slot=$('new-slot').value.trim(),label=$('new-label').value.trim()||slot;
    if(!/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/.test(slot)||/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i.test(slot)){$('account-output').textContent='请填写 1–32 个英文字母、数字、下划线或短横线，以字母或数字开头，避开 CON、NUL 等系统保留名称；显示名称可以使用中文。';$('new-slot').focus();return;}
    const value=await action('account-label',{slot,label},'account-output');if(value?.state==='completed'){$('new-slot').value='';$('new-label').value='';}
  });
  $('account-check').addEventListener('click',async()=>{
    if(busy||$('start').disabled)return;
    $('account-output').textContent='';
    page('audit');$('learning-panel').hidden=true;$('audit-content').hidden=false;
    if(retest)await retest();page('accounts');$('account-readiness').scrollIntoView({block:'nearest'});
  });
  $('account-view-checks').addEventListener('click',()=>{
    page('audit');$('learning-panel').hidden=true;$('audit-content').hidden=false;
    if(!$('desktop-handoff').hidden){$('desktop-conditions').open=true;$('desktop-conditions').scrollIntoView({block:'center'});}else $('start').focus();
  });
  document.addEventListener('envscope-report',event=>{
    const {report,source}=event.detail;
    $('account-readiness').textContent=(source==='history'?'这是历史报告，切换前仍需新检测。 ':'')+(report.launch?.ready?'本轮启动条件已核实，切换时还会复检。':(report.launch?.reasons?.slice(0,3).join('；')||'启动条件尚未完整确认，请先检测。'));
  });
  document.addEventListener('envscope-audit-start',()=>{$('account-readiness').textContent='正在检测启动条件，等待本轮结果。';});
  document.addEventListener('envscope-audit-end',event=>{if(!event.detail.has_report)$('account-readiness').textContent='本轮检测未完成，请重新检测；未沿用旧结论。';});
  for(const id of ["account-export","account-import"])$(id).addEventListener("click",()=>action(id,{slot:$("archive-slot").value.trim(),file:$("archive-path").value.trim()},"account-output",
    id==="account-export"?"将创建未加密的账号目录备份。文件含登录资料，请保存在受保护的本机目录。":"将读取指定目录并导入空的非活动槽位。不会覆盖现有槽位。"));
  for(const mode of ['export','import']){
    $('encrypted-choose-'+mode).addEventListener('click',()=>action('archive-choose-file',{mode},'account-output'));
    $('encrypted-'+mode).addEventListener('click',async()=>{
      const input=$('encrypted-password');if(input.value.length<12){$('account-output').textContent='请填写至少 12 个字符的存档密码。';input.focus();return;}
      try{await action('archive-'+mode,{slot:$('encrypted-slot').value.trim(),file:$('encrypted-path').value.trim(),password:input.value},'account-output',mode==='export'?'将复制非活动槽位，在受限临时目录中打包，使用密码加密并校验后导出。密码不会保存；临时明文随后清理。':'将用密码验证存档完整性和全部文件，再导入空槽位。不覆盖现有资料，不启动 Claude。');}finally{input.value='';}
    });
  }
  $('browser-cleanup').addEventListener('click',()=>action('browser-cleanup',{},'tool-output'));
  $("proxy-found").addEventListener("change",()=>{$("proxy-url").value=$("proxy-found").value;});
  $("proxy-test").addEventListener("click",()=>action("proxy-diagnose",{proxy:$("proxy-url").value.trim()}));
  $("cli-info").addEventListener("click",()=>action("cli-info",{},'environment-output'));$("device-info").addEventListener("click",()=>action("fingerprint",{},'environment-output'));
  $("support-bundle").addEventListener("click",()=>action("support-bundle",{},'environment-output'));
  $("browser-info").addEventListener("click",async()=>{
    const result={language:navigator.languages,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,screen:{width:screen.width,height:screen.height,colorDepth:screen.colorDepth},hardwareThreads:navigator.hardwareConcurrency||null};
    try{const canvas=document.createElement("canvas");canvas.width=220;canvas.height=40;const c=canvas.getContext("2d");c.font="16px sans-serif";c.fillText("EnvScope 0123456789",3,24);
      const bytes=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(canvas.toDataURL()));result.canvas_sha256=[...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,"0")).join("");
    }catch{result.canvas_sha256="unavailable";}
    try{const gl=document.createElement("canvas").getContext("webgl");const ext=gl?.getExtension("WEBGL_debug_renderer_info");result.webgl=ext?{vendor:gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),renderer:gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)}:"unavailable_or_limited";gl?.getExtension("WEBGL_lose_context")?.loseContext();}
    catch{result.webgl="unavailable";}
    information({title:'浏览器信息',rows:[{label:'语言',value:result.language.join('、')},{label:'时区',value:result.timezone},{label:'屏幕',value:`${result.screen.width} × ${result.screen.height}`},{label:'逻辑线程数',value:result.hardwareThreads},{label:'图形渲染器',value:typeof result.webgl==='object'?result.webgl.renderer:'浏览器未提供或限制访问'},{label:'画布摘要',value:result.canvas_sha256}],note:'仅在本页展示，未上传；缺少图形或画布信息不代表故障，也不构成账号风险结论。'});
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
  document.addEventListener("envscope-audit-complete",event=>{lastReportId=event.detail?.report_id||null;void refresh().catch(()=>{});});
  document.addEventListener('envscope-maintenance-change',()=>{void refresh().catch(()=>{});});
  setInterval(async()=>{
    if(document.hidden||($('page-upkeep').hidden&&($('page-audit').hidden||!catalog?.maintenance?.enabled))||busy||$('start').disabled||document.documentElement.dataset.operationBusy==='true')return;
    try{
      const response=await fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-EnvScope-Token':session.token},body:JSON.stringify({action:'maintenance-status',params:{},confirmed:false})});
      if(response.ok){const value=await response.json();renderUpkeep(value.maintenance);document.dispatchEvent(new CustomEvent('envscope-maintenance-status',{detail:value.maintenance}));}
    }catch{/* Keep the explicit last completion time; never fabricate a new heartbeat. */}
  },15000);
  try{await refresh();}catch(error){$("backend-note").textContent=error.message;document.dispatchEvent(new CustomEvent('envscope-catalog-error'));}
}
